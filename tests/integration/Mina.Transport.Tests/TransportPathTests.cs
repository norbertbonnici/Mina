using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Mina.ControlPlane.Pki;
using Mina.EndpointAgent.Proxy;

namespace Mina.Transport.Tests;

/// <summary>
/// End-to-end proof of the ADR-0001 Option C transport path, entirely in-process:
///   browser → loopback CONNECT proxy → mTLS tunnel → egress (CONNECT terminator) → target.
/// These assert the properties the transport choice rests on: only mutually-authenticated
/// sessions tunnel, the path carries arbitrary bytes, and loss of the tunnel fails closed.
/// </summary>
public sealed class TransportPathTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;

    [Fact]
    public async Task Bytes_flow_browser_to_target_through_the_full_tunnel()
    {
        using var ca = CertificateAuthority.Create("Mina Transport Test CA", Now.AddMinutes(-5), TimeSpan.FromDays(1));
        using var serverCert = ca.IssueServerCertificate(
            "egress.local", ["egress.local"], [IPAddress.Loopback], Now.AddMinutes(-5), TimeSpan.FromHours(1));
        using var caPublic = ca.PublicCertificate;

        await using var target = new TcpEchoServer();
        await using var egress = new TestEgress(serverCert, caPublic);

        var factory = MakeFactory(ca, egress.Endpoint);
        await using var proxy = new LoopbackConnectProxy(factory, new LoopbackPeerAuthorizer(), NullLogger<LoopbackConnectProxy>.Instance);
        proxy.Start();

        var echoed = await BrowserRoundTripAsync(proxy.Endpoint!, new ConnectTarget("127.0.0.1", target.Port), "hello-mina");

        Assert.Equal("hello-mina", echoed);
    }

    [Fact]
    public async Task Large_payload_survives_the_tunnel_intact()
    {
        using var ca = CertificateAuthority.Create("Mina Transport Test CA", Now.AddMinutes(-5), TimeSpan.FromDays(1));
        using var serverCert = ca.IssueServerCertificate(
            "egress.local", ["egress.local"], [IPAddress.Loopback], Now.AddMinutes(-5), TimeSpan.FromHours(1));
        using var caPublic = ca.PublicCertificate;

        await using var target = new TcpEchoServer();
        await using var egress = new TestEgress(serverCert, caPublic);
        var factory = MakeFactory(ca, egress.Endpoint);
        await using var proxy = new LoopbackConnectProxy(factory, new LoopbackPeerAuthorizer(), NullLogger<LoopbackConnectProxy>.Instance);
        proxy.Start();

        var payload = string.Concat(Enumerable.Repeat("The quick brown fox 0123456789. ", 5000));
        var echoed = await BrowserRoundTripAsync(proxy.Endpoint!, new ConnectTarget("127.0.0.1", target.Port), payload);

        Assert.Equal(payload, echoed);
    }

    [Fact]
    public async Task Tunnel_failure_fails_closed_with_502_and_no_direct_connection()
    {
        // Egress endpoint that is not listening: the tunnel cannot be established.
        var deadEgress = new IPEndPoint(IPAddress.Loopback, GetUnusedPort());
        using var ca = CertificateAuthority.Create("Mina Transport Test CA", Now.AddMinutes(-5), TimeSpan.FromDays(1));
        var factory = MakeFactory(ca, deadEgress);

        await using var proxy = new LoopbackConnectProxy(factory, new LoopbackPeerAuthorizer(), NullLogger<LoopbackConnectProxy>.Instance);
        proxy.Start();

        var (status, _) = await BrowserConnectAsync(proxy.Endpoint!, new ConnectTarget("example.org", 443));

        Assert.Equal(502, status); // fail closed — an error, never a direct path to the target
    }

    [Fact]
    public async Task Egress_rejects_a_client_certificate_from_an_untrusted_ca()
    {
        using var egressCa = CertificateAuthority.Create("Mina Egress CA", Now.AddMinutes(-5), TimeSpan.FromDays(1));
        using var serverCert = egressCa.IssueServerCertificate(
            "egress.local", ["egress.local"], [IPAddress.Loopback], Now.AddMinutes(-5), TimeSpan.FromHours(1));
        using var egressCaPublic = egressCa.PublicCertificate;

        // The agent presents a certificate from a DIFFERENT CA the egress does not trust.
        using var rogueCa = CertificateAuthority.Create("Rogue CA", Now.AddMinutes(-5), TimeSpan.FromDays(1));

        await using var egress = new TestEgress(serverCert, egressCaPublic);
        var factory = MakeFactory(rogueCa, egress.Endpoint, trustCa: egressCa);

        await using var proxy = new LoopbackConnectProxy(factory, new LoopbackPeerAuthorizer(), NullLogger<LoopbackConnectProxy>.Instance);
        proxy.Start();

        var (status, _) = await BrowserConnectAsync(proxy.Endpoint!, new ConnectTarget("example.org", 443));

        Assert.Equal(502, status);       // handshake rejected ⇒ tunnel fails ⇒ fail closed
        Assert.True(egress.ClientAuthFailures >= 1);
    }

    [Fact]
    public async Task Loopback_peer_authorizer_admits_a_loopback_connection()
    {
        using var listener = new Socket(SocketType.Stream, ProtocolType.Tcp);
        listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        listener.Listen();
        var endpoint = (IPEndPoint)listener.LocalEndPoint!;

        using var client = new Socket(SocketType.Stream, ProtocolType.Tcp);
        await client.ConnectAsync(endpoint);
        using var accepted = await listener.AcceptAsync();

        var authorized = await new LoopbackPeerAuthorizer().AuthorizeAsync(accepted, CancellationToken.None);

        Assert.True(authorized);
    }

    private static MtlsTunnelConnectionFactory MakeFactory(
        CertificateAuthority clientCa, IPEndPoint egress, CertificateAuthority? trustCa = null)
    {
        using var sessionCert = clientCa.IssueClientCertificate(
            "mina-session-test", "mina:session:test", Now.AddMinutes(-5), TimeSpan.FromMinutes(60));
        var pfx = sessionCert.Export(X509ContentType.Pkcs12);

        var trusted = (trustCa ?? clientCa).PublicCertificate;
        return new MtlsTunnelConnectionFactory(
            new EgressEndpoint(egress.Address.ToString(), egress.Port, "egress.local"),
            () => X509CertificateLoader.LoadPkcs12(pfx, password: null),
            trusted);
    }

    private static async Task<string> BrowserRoundTripAsync(IPEndPoint proxy, ConnectTarget target, string payload)
    {
        using var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
        await socket.ConnectAsync(proxy);
        await using var stream = new NetworkStream(socket, ownsSocket: false);

        await stream.WriteAsync(HttpConnect.BuildConnectRequest(target));
        var status = await HttpConnect.ReadResponseStatusAsync(stream, CancellationToken.None);
        Assert.Equal(200, status);

        var bytes = Encoding.UTF8.GetBytes(payload);
        await stream.WriteAsync(bytes);

        var received = new byte[bytes.Length];
        var offset = 0;
        while (offset < received.Length)
        {
            var read = await stream.ReadAsync(received.AsMemory(offset));
            if (read == 0)
            {
                break;
            }

            offset += read;
        }

        return Encoding.UTF8.GetString(received, 0, offset);
    }

    private static async Task<(int Status, string Head)> BrowserConnectAsync(IPEndPoint proxy, ConnectTarget target)
    {
        using var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
        await socket.ConnectAsync(proxy);
        await using var stream = new NetworkStream(socket, ownsSocket: false);

        await stream.WriteAsync(HttpConnect.BuildConnectRequest(target));
        var status = await HttpConnect.ReadResponseStatusAsync(stream, CancellationToken.None);
        return (status, string.Empty);
    }

    private static int GetUnusedPort()
    {
        using var probe = new Socket(SocketType.Stream, ProtocolType.Tcp);
        probe.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return ((IPEndPoint)probe.LocalEndPoint!).Port;
    }
}
