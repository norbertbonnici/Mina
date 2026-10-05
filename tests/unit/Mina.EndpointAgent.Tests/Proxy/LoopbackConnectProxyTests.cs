using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Mina.EndpointAgent.Proxy;
using Mina.EndpointAgent.Session;

namespace Mina.EndpointAgent.Tests.Proxy;

/// <summary>
/// The loopback proxy's own tamper reporting (M2-4): only a live session opens this listener at
/// all, so anything the peer authorizer refuses here is THREAT_MODEL B1's "foreign process rides
/// the tunnel" case, not routine traffic — see <see cref="WindowsPeerAuthorizerTests"/> for the
/// authorizer itself.
/// </summary>
public sealed class LoopbackConnectProxyTests
{
    [Fact]
    public async Task A_rejected_peer_is_reported_as_a_foreign_proxy_client()
    {
        var sessionId = Guid.NewGuid();
        var reporter = new RecordingTamperReporter();
        await using var proxy = new LoopbackConnectProxy(
            new UnusedTunnelFactory(), new RejectingPeerAuthorizer(), NullLogger<LoopbackConnectProxy>.Instance,
            reporter, sessionId);
        proxy.Start();

        using var client = new TcpClient();
        await client.ConnectAsync(proxy.Endpoint!.Address, proxy.Endpoint.Port);
        await using var stream = client.GetStream();
        await stream.WriteAsync(Encoding.ASCII.GetBytes("CONNECT example.org:443 HTTP/1.1\r\n\r\n"));

        // Reading to completion or reset is the synchronisation point: HandleConnectionAsync
        // always reports the indicator before it writes a response at all, so by the time the
        // client's read returns anything -- including a reset -- the server side is done. The
        // response's exact bytes are not asserted on: the server disposes the socket immediately
        // after writing, without a graceful shutdown handshake, and a hard RST can race ahead of
        // already-written bytes actually reaching this side (a real, pre-existing quirk of
        // HandleConnectionAsync's own socket lifetime, not something this test should have to
        // out-wait to prove the tamper report happened).
        await ReadToCloseAsync(stream);

        var reported = Assert.Single(reporter.Reported);
        Assert.Equal(TamperIndicators.ForeignProxyClient, reported.Indicator);
        Assert.Equal(sessionId, reported.SessionId);
    }

    private static async Task ReadToCloseAsync(NetworkStream stream)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var buffer = new byte[256];
        try
        {
            while (await stream.ReadAsync(buffer, timeout.Token) > 0)
            {
                // draining; see the caller's remarks on why the content itself is not asserted on
            }
        }
        catch (Exception ex) when (ex is IOException or SocketException)
        {
            // Ordinary abrupt teardown -- see the caller's remarks.
        }
    }

    [Fact]
    public async Task An_authorized_peer_reports_nothing()
    {
        var reporter = new RecordingTamperReporter();
        await using var proxy = new LoopbackConnectProxy(
            new UnusedTunnelFactory(), new LoopbackPeerAuthorizer(), NullLogger<LoopbackConnectProxy>.Instance,
            reporter);
        proxy.Start();

        using var client = new TcpClient();
        await client.ConnectAsync(proxy.Endpoint!.Address, proxy.Endpoint.Port);
        await using var stream = client.GetStream();
        await stream.WriteAsync(Encoding.ASCII.GetBytes("CONNECT example.org:443 HTTP/1.1\r\n\r\n"));

        await ReadToCloseAsync(stream);

        Assert.Empty(reporter.Reported);
    }

    private sealed class RejectingPeerAuthorizer : IPeerAuthorizer
    {
        public ValueTask<bool> AuthorizeAsync(Socket clientSocket, CancellationToken cancellationToken) =>
            ValueTask.FromResult(false);
    }

    private sealed class UnusedTunnelFactory : ITunnelConnectionFactory
    {
        public Task<Stream> ConnectAsync(ConnectTarget target, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("A rejected peer must never reach the tunnel factory.");
    }
}
