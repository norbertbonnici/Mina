using Microsoft.Extensions.Options;
using Mina.EndpointAgent.Configuration;
using Mina.EndpointAgent.Proxy;
using Mina.EndpointAgent.Session;

namespace Mina.EndpointAgent;

/// <summary>
/// Runs the protected path: hold a research session, and keep the loopback proxy listening exactly
/// as long as that session is live. When the session goes away — revoked, lapsed, renewal refused,
/// control plane unreachable — the listener is torn down, so the research browser gets a connection
/// error instead of quietly reaching the internet through ordinary corporate egress (FR-007).
/// </summary>
/// <remarks>
/// Launching and pinning the research browser to the proxy port, WFP enforcement and the tray UI
/// are the Windows-specific parts and land with M2-4; this worker is the platform-neutral core they
/// build on.
/// </remarks>
internal sealed partial class ProtectedPathWorker(
    ResearchSessionManager sessions,
    SessionTunnelConnectionFactory tunnelFactory,
    IPeerAuthorizer peerAuthorizer,
    IOptions<MinaAgentOptions> options,
    ILoggerFactory loggerFactory,
    TimeProvider clock,
    ILogger<ProtectedPathWorker> logger) : BackgroundService
{
    private readonly MinaAgentOptions _options = options.Value;
    private LoopbackConnectProxy? _proxy;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                await TickAsync(stoppingToken).ConfigureAwait(false);
                await Task.Delay(_options.PollInterval, clock, stoppingToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // normal shutdown
        }
        finally
        {
            await CloseProtectedPathAsync().ConfigureAwait(false);
            await sessions.EndAsync(CancellationToken.None).ConfigureAwait(false);
        }
    }

    private async Task TickAsync(CancellationToken cancellationToken)
    {
        try
        {
            if (sessions.Current is null)
            {
                await sessions.EstablishAsync(cancellationToken).ConfigureAwait(false);
                await OpenProtectedPathAsync().ConfigureAwait(false);
                return;
            }

            await sessions.RenewIfDueAsync(cancellationToken).ConfigureAwait(false);
            if (sessions.Current is null)
            {
                await CloseProtectedPathAsync().ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is ControlPlaneException or HttpRequestException
                                   || (ex is OperationCanceledException && !cancellationToken.IsCancellationRequested))
        {
            // An HTTP timeout arrives as TaskCanceledException, which is an OperationCanceledException.
            // Letting it escape broke the worker's loop outright: the path closed, correctly, but
            // never reopened without a service restart. A timeout is transient — close the path and
            // try again on the next tick.
            Log.SessionUnavailable(logger, ex.Message);
            await CloseProtectedPathAsync().ConfigureAwait(false);
        }
    }

    private async Task OpenProtectedPathAsync()
    {
        await CloseProtectedPathAsync().ConfigureAwait(false);

        var proxy = new LoopbackConnectProxy(
            tunnelFactory, peerAuthorizer, loggerFactory.CreateLogger<LoopbackConnectProxy>());
        proxy.Start(_options.LoopbackPort);
        _proxy = proxy;

        Log.ProtectedPathOpen(logger, proxy.Endpoint?.Port ?? 0);
    }

    private async Task CloseProtectedPathAsync()
    {
        if (_proxy is null)
        {
            return;
        }

        await _proxy.DisposeAsync().ConfigureAwait(false);
        _proxy = null;
        Log.ProtectedPathClosed(logger);
    }

    private static partial class Log
    {
        [LoggerMessage(Level = LogLevel.Information,
            Message = "Protected path open; research browser proxy listening on 127.0.0.1:{Port}.")]
        public static partial void ProtectedPathOpen(ILogger logger, int port);

        [LoggerMessage(Level = LogLevel.Warning,
            Message = "Protected path closed; the research browser has no route out until a session is re-established.")]
        public static partial void ProtectedPathClosed(ILogger logger);

        [LoggerMessage(Level = LogLevel.Warning, Message = "Could not obtain or keep a research session: {Reason}")]
        public static partial void SessionUnavailable(ILogger logger, string reason);
    }
}
