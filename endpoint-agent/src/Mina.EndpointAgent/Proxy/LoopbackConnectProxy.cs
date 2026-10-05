using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using Mina.EndpointAgent.Session;

namespace Mina.EndpointAgent.Proxy;

/// <summary>
/// The loopback HTTP CONNECT proxy the research browser is pinned to (ADR-0001 Option C). It
/// binds to a loopback address only, authorises the connecting peer, and forwards every request
/// through the tunnel factory. If a tunnel cannot be established it returns an HTTP error and
/// closes — it never connects directly, so loss of the protected path fails closed.
/// </summary>
public sealed partial class LoopbackConnectProxy(
    ITunnelConnectionFactory tunnelFactory,
    IPeerAuthorizer peerAuthorizer,
    ILogger<LoopbackConnectProxy> logger,
    ITamperReporter? tamperReporter = null,
    Guid? sessionId = null) : IAsyncDisposable
{
    private readonly ITunnelConnectionFactory _tunnelFactory =
        tunnelFactory ?? throw new ArgumentNullException(nameof(tunnelFactory));

    private readonly IPeerAuthorizer _peerAuthorizer =
        peerAuthorizer ?? throw new ArgumentNullException(nameof(peerAuthorizer));

    private TcpListener? _listener;
    private CancellationTokenSource? _cts;
    private Task? _acceptLoop;

    /// <summary>The loopback endpoint the proxy is listening on (valid after <see cref="Start"/>).</summary>
    public IPEndPoint? Endpoint => _listener?.LocalEndpoint as IPEndPoint;

    /// <summary>Starts listening on 127.0.0.1:<paramref name="port"/> (0 picks a free port).</summary>
    public void Start(int port = 0)
    {
        ObjectDisposedException.ThrowIf(_listener is not null, this);
        _cts = new CancellationTokenSource();
        _listener = new TcpListener(IPAddress.Loopback, port);
        _listener.Start();
        _acceptLoop = AcceptLoopAsync(_listener, _cts.Token);
    }

    private async Task AcceptLoopAsync(TcpListener listener, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            Socket socket;
            try
            {
                socket = await listener.AcceptSocketAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (SocketException)
            {
                continue;
            }

            _ = HandleConnectionAsync(socket, ct);
        }
    }

    private async Task HandleConnectionAsync(Socket socket, CancellationToken ct)
    {
        using var connection = socket;
        await using var client = new NetworkStream(socket, ownsSocket: false);
        try
        {
            if (!await _peerAuthorizer.AuthorizeAsync(socket, ct).ConfigureAwait(false))
            {
                Log.PeerRejected(logger, socket.RemoteEndPoint?.ToString() ?? "unknown");

                // Only a real session opens this listener at all (ProtectedPathWorker starts it
                // after establishing one and stops it before ending one), so anything that reaches
                // here and is not the managed browser is exactly THREAT_MODEL B1's "foreign process
                // rides the tunnel" spoof case, not routine traffic.
                tamperReporter?.Report(TamperIndicators.ForeignProxyClient, sessionId);

                await WriteAsync(client, HttpConnect.BuildErrorResponse(403, "Forbidden"), ct).ConfigureAwait(false);
                return;
            }

            ConnectTarget target;
            try
            {
                target = await HttpConnect.ReadConnectRequestAsync(client, ct).ConfigureAwait(false);
            }
            catch (HttpConnectException ex)
            {
                Log.BadRequest(logger, ex.Message);
                await WriteAsync(client, HttpConnect.BuildErrorResponse(400, "Bad Request"), ct).ConfigureAwait(false);
                return;
            }

            Stream tunnel;
            try
            {
                tunnel = await _tunnelFactory.ConnectAsync(target, ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // Fail closed: the tunnel is the only path out. No direct fallback, ever.
                Log.TunnelFailed(logger, target, ex.Message);
                await WriteAsync(client, HttpConnect.BuildErrorResponse(502, "Bad Gateway"), ct).ConfigureAwait(false);
                return;
            }

            await using (tunnel)
            {
                await WriteAsync(client, HttpConnect.ConnectionEstablished, ct).ConfigureAwait(false);
                Log.TunnelEstablished(logger, target);
                await PumpAsync(client, tunnel, ct).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is IOException or OperationCanceledException or SocketException)
        {
            // Ordinary connection teardown; nothing actionable.
        }
    }

    private static async Task WriteAsync(Stream stream, ReadOnlyMemory<byte> data, CancellationToken ct)
    {
        await stream.WriteAsync(data, ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);
    }

    /// <summary>Bidirectionally copies until either side ends, then tears both down.</summary>
    private static async Task PumpAsync(Stream a, Stream b, CancellationToken ct)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var one = a.CopyToAsync(b, linked.Token);
        var two = b.CopyToAsync(a, linked.Token);
        await Task.WhenAny(one, two).ConfigureAwait(false);
        await linked.CancelAsync().ConfigureAwait(false);
        try
        {
            await Task.WhenAll(one, two).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or OperationCanceledException or SocketException)
        {
            // expected once one direction is cancelled
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_cts is not null)
        {
            await _cts.CancelAsync().ConfigureAwait(false);
        }

        _listener?.Stop();

        if (_acceptLoop is not null)
        {
            try
            {
                await _acceptLoop.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // expected
            }
        }

        _cts?.Dispose();
        _listener = null;
    }

    private static partial class Log
    {
        [LoggerMessage(Level = LogLevel.Warning, Message = "Rejected loopback peer {Peer}.")]
        public static partial void PeerRejected(ILogger logger, string peer);

        [LoggerMessage(Level = LogLevel.Debug, Message = "Bad CONNECT request: {Reason}.")]
        public static partial void BadRequest(ILogger logger, string reason);

        [LoggerMessage(Level = LogLevel.Warning, Message = "Tunnel to {Target} failed: {Reason}. Failing closed.")]
        public static partial void TunnelFailed(ILogger logger, ConnectTarget target, string reason);

        [LoggerMessage(Level = LogLevel.Debug, Message = "Tunnel established to {Target}.")]
        public static partial void TunnelEstablished(ILogger logger, ConnectTarget target);
    }
}
