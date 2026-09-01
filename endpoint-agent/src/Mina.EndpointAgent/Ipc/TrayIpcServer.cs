using System.IO.Pipes;
using Microsoft.Extensions.Options;
using Mina.EndpointAgent.Configuration;

namespace Mina.EndpointAgent.Ipc;

/// <summary>
/// Serves the tray over a local named pipe. The agent runs as SYSTEM and the tray as the
/// interactive user, so this is a privilege boundary: everything arriving here is untrusted input
/// from a process the analyst controls, and is validated by <see cref="TrayControlService"/> before
/// anything happens.
/// </summary>
public sealed partial class TrayIpcServer(
    ITrayControl control,
    IOptions<MinaAgentOptions> options,
    ILogger<TrayIpcServer> logger) : BackgroundService
{
    private readonly MinaAgentOptions _options =
        (options ?? throw new ArgumentNullException(nameof(options))).Value;

    /// <summary>The pipe name in use. Overridable only for tests, which need isolated pipes.</summary>
    public string PipeName { get; init; } = TrayProtocol.PipeName;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_options.TrayPipe.Enabled)
        {
            Log.Disabled(logger);
            return;
        }

        NamedPipeServerStream seed;
        try
        {
            // FirstPipeInstance fails if the name already exists. On a healthy endpoint the agent
            // starts before any user code, so nothing should hold it — if something does, either a
            // second agent is running or a local process has squatted the name to sit between the
            // analyst and the agent. Neither is survivable, so the agent stops instead of serving
            // a tray it cannot vouch for (THREAT_MODEL B1).
            seed = CreateInstance(firstInstance: true);
        }
        catch (IOException ex)
        {
            Log.PipeNameTaken(logger, PipeName, ex.Message);
            throw new InvalidOperationException(
                $"The named pipe '{PipeName}' already exists. The agent will not share it.", ex);
        }

        Log.Listening(logger, PipeName, _options.TrayPipe.Instances);

        var loops = new List<Task>(_options.TrayPipe.Instances) { AcceptLoopAsync(seed, stoppingToken) };
        for (var i = 1; i < _options.TrayPipe.Instances; i++)
        {
            loops.Add(AcceptLoopAsync(seeded: null, stoppingToken));
        }

        await Task.WhenAll(loops).ConfigureAwait(false);
    }

    private async Task AcceptLoopAsync(NamedPipeServerStream? seeded, CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            var pipe = seeded ?? CreateInstance(firstInstance: false);
            seeded = null;

            try
            {
                await pipe.WaitForConnectionAsync(stoppingToken).ConfigureAwait(false);
                await ServeAsync(pipe, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (IOException ex)
            {
                // A client that vanished mid-exchange. Normal: the tray disconnects when its panel
                // closes, and Windows reports that as a broken pipe.
                Log.ConnectionDropped(logger, ex.Message);
            }
            finally
            {
                await pipe.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    private async Task ServeAsync(NamedPipeServerStream pipe, CancellationToken stoppingToken)
    {
        var client = ReadClientIdentity(pipe);
        Log.ClientConnected(logger, client ?? "unidentified");

        while (pipe.IsConnected && !stoppingToken.IsCancellationRequested)
        {
            TrayRequest? request;
            using (var idle = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken))
            {
                idle.CancelAfter(TrayProtocol.IdleTimeout);
                try
                {
                    request = await TrayFraming
                        .ReadAsync(pipe, TrayJsonContext.Default.TrayRequest, idle.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (!stoppingToken.IsCancellationRequested)
                {
                    Log.IdleTimeout(logger, client ?? "unidentified");
                    return;
                }
                catch (TrayProtocolException ex)
                {
                    // Malformed input from a local process. Say so once, then close: continuing to
                    // read from a peer that is not speaking the protocol only keeps the instance
                    // occupied.
                    Log.MalformedFrame(logger, client ?? "unidentified", ex.Message);
                    await TryWriteAsync(
                        pipe,
                        TrayResponse.Failure(TrayErrorCodes.InvalidRequest, "The agent could not read that request."),
                        stoppingToken).ConfigureAwait(false);
                    return;
                }
            }

            if (request is null)
            {
                return;
            }

            var response = await ExecuteSafelyAsync(request, client, stoppingToken).ConfigureAwait(false);

            using var exchange = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
            exchange.CancelAfter(TrayProtocol.ExchangeTimeout);
            await TrayFraming
                .WriteAsync(pipe, response, TrayJsonContext.Default.TrayResponse, exchange.Token)
                .ConfigureAwait(false);
        }
    }

    private async Task<TrayResponse> ExecuteSafelyAsync(
        TrayRequest request, string? client, CancellationToken stoppingToken)
    {
        try
        {
            return await control.ExecuteAsync(request, client, stoppingToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // A fault handling one tray request must not take down the pipe, and must not leak the
            // exception text to a user-mode process — it goes to the agent's log instead.
            Log.OperationFaulted(logger, request.Op, ex);
            return TrayResponse.Failure(
                TrayErrorCodes.AgentFault, "The agent could not complete that action. It has been logged.");
        }
    }

    private static async Task TryWriteAsync(
        NamedPipeServerStream pipe, TrayResponse response, CancellationToken cancellationToken)
    {
        try
        {
            await TrayFraming
                .WriteAsync(pipe, response, TrayJsonContext.Default.TrayResponse, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or OperationCanceledException)
        {
            // Best effort; the peer is already misbehaving or gone.
        }
    }

    private NamedPipeServerStream CreateInstance(bool firstInstance)
    {
        var pipeOptions = PipeOptions.Asynchronous | PipeOptions.WriteThrough;
        if (firstInstance)
        {
            pipeOptions |= PipeOptions.FirstPipeInstance;
        }

        if (!OperatingSystem.IsWindows())
        {
            // Unix has no pipe DACL; .NET backs named pipes with a Unix-domain socket whose
            // permissions come from the process umask. The agent only ever runs as a Windows
            // service in production — this path exists so the IPC layer can be exercised on CI's
            // Linux hosts, and it is not a supported deployment.
            return new NamedPipeServerStream(
                PipeName, PipeDirection.InOut, _options.TrayPipe.Instances,
                PipeTransmissionMode.Byte, pipeOptions);
        }

        return NamedPipeServerStreamAcl.Create(
            PipeName,
            PipeDirection.InOut,
            _options.TrayPipe.Instances,
            PipeTransmissionMode.Byte,
            pipeOptions,
            inBufferSize: TrayProtocol.MaxFrameBytes,
            outBufferSize: TrayProtocol.MaxFrameBytes,
            TrayPipeSecurity.Create());
    }

    /// <summary>
    /// The account on the other end, for the agent's own log. It is an attribution aid, not an
    /// authorisation input: the DACL decides who may connect, and every operation is authorised on
    /// its own merits.
    /// </summary>
    private static string? ReadClientIdentity(NamedPipeServerStream pipe)
    {
        if (!OperatingSystem.IsWindows())
        {
            return null;
        }

        try
        {
            return pipe.GetImpersonationUserName();
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException)
        {
            return null;
        }
    }

    private static partial class Log
    {
        [LoggerMessage(Level = LogLevel.Information,
            Message = "Tray IPC listening on pipe '{PipeName}' with {Instances} instances.")]
        public static partial void Listening(ILogger logger, string pipeName, int instances);

        [LoggerMessage(Level = LogLevel.Information, Message = "Tray IPC is disabled by configuration.")]
        public static partial void Disabled(ILogger logger);

        [LoggerMessage(Level = LogLevel.Critical,
            Message = "Pipe '{PipeName}' already exists, so the agent cannot be the only listener on it: {Reason}. " +
                      "This is a tamper indicator — a local process may be impersonating the agent to the tray.")]
        public static partial void PipeNameTaken(ILogger logger, string pipeName, string reason);

        [LoggerMessage(Level = LogLevel.Debug, Message = "Tray client {Client} connected.")]
        public static partial void ClientConnected(ILogger logger, string client);

        [LoggerMessage(Level = LogLevel.Debug, Message = "Tray connection dropped: {Reason}")]
        public static partial void ConnectionDropped(ILogger logger, string reason);

        [LoggerMessage(Level = LogLevel.Debug, Message = "Closing idle tray connection from {Client}.")]
        public static partial void IdleTimeout(ILogger logger, string client);

        [LoggerMessage(Level = LogLevel.Warning,
            Message = "Tray client {Client} sent a frame the agent could not read: {Reason}")]
        public static partial void MalformedFrame(ILogger logger, string client, string reason);

        [LoggerMessage(Level = LogLevel.Error, Message = "Tray operation {Operation} faulted.")]
        public static partial void OperationFaulted(ILogger logger, string operation, Exception exception);
    }
}
