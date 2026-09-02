using System.Net;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Mina.ControlPlane.Pki;
using Mina.EndpointAgent.Configuration;
using Mina.EndpointAgent.Proxy;
using Mina.EndpointAgent.Session;
using Mina.TestSupport;

namespace Mina.Agent.E2E.Tests;

/// <summary>
/// The whole stack in one process: research target ← egress ← agent tunnel ← loopback proxy, with
/// the real control-plane API issuing the session certificate that authenticates the tunnel.
/// </summary>
internal sealed class MinaTestEnvironment : IAsyncDisposable
{
    private const string ServerName = "egress.local";

    private readonly CertificateAuthority _ca;
    private readonly X509Certificate2 _serverCertificate;
    private readonly X509Certificate2 _caPublic;
    private LoopbackConnectProxy? _proxy;

    private MinaTestEnvironment(
        CertificateAuthority ca,
        X509Certificate2 serverCertificate,
        X509Certificate2 caPublic,
        TcpEchoServer target,
        TestEgress egress,
        ControlPlaneHost controlPlane,
        HttpClient httpClient,
        ResearchSessionManager sessions,
        SessionTunnelConnectionFactory tunnelFactory)
    {
        _ca = ca;
        _serverCertificate = serverCertificate;
        _caPublic = caPublic;
        Target = target;
        Egress = egress;
        ControlPlane = controlPlane;
        HttpClient = httpClient;
        Sessions = sessions;
        TunnelFactory = tunnelFactory;
    }

    public TcpEchoServer Target { get; }

    public TestEgress Egress { get; }

    public ControlPlaneHost ControlPlane { get; }

    public HttpClient HttpClient { get; }

    public ResearchSessionManager Sessions { get; }

    public SessionTunnelConnectionFactory TunnelFactory { get; }

    public ConnectTarget ResearchTarget => new("127.0.0.1", Target.Port);

    public static MinaTestEnvironment Create(
        string region = "westeurope",
        TimeSpan? leaseTtl = null,
        TimeSpan? renewMargin = null,
        string roles = "Mina.Analyst",
        string? device = "device-1")
    {
        var now = DateTimeOffset.UtcNow;
        var ca = CertificateAuthority.Create("Mina E2E CA", now.AddMinutes(-5), TimeSpan.FromDays(1));
        var caPublic = ca.PublicCertificate;
        var serverCertificate = ca.IssueServerCertificate(
            ServerName, [ServerName], [IPAddress.Loopback], now.AddMinutes(-5), TimeSpan.FromHours(1));

        var target = new TcpEchoServer();
        var egress = new TestEgress(serverCertificate, caPublic);

        var controlPlane = new ControlPlaneHost(
            ca, egress.Endpoint.Address.ToString(), egress.Endpoint.Port, ServerName,
            leaseTtl ?? TimeSpan.FromMinutes(60));

        var httpClient = controlPlane.CreateClient();
        var tokenProvider = new ConfiguredAccessTokenProvider(
            BearerTestAuthHandler.Token("oid-analyst", "analyst@fiaumalta.org", device, roles));

        var options = Options.Create(new MinaAgentOptions
        {
            Region = region,
            EgressCaCertificatePem = caPublic.ExportCertificatePem(),
            RenewMargin = renewMargin ?? TimeSpan.FromMinutes(10),
        });

        var sessions = new ResearchSessionManager(
            new ControlPlaneClient(httpClient, tokenProvider),
            options,
            TimeProvider.System,
            NullLogger<ResearchSessionManager>.Instance);

        return new MinaTestEnvironment(
            ca, serverCertificate, caPublic, target, egress, controlPlane, httpClient, sessions,
            new SessionTunnelConnectionFactory(sessions));
    }

    /// <summary>Starts the loopback proxy, as the agent worker does once a session is live.</summary>
    public IPEndPoint StartProxy()
    {
        _proxy = new LoopbackConnectProxy(
            TunnelFactory, new LoopbackPeerAuthorizer(), NullLogger<LoopbackConnectProxy>.Instance);
        _proxy.Start();
        return _proxy.Endpoint!;
    }

    /// <summary>A second client for the same analyst, to act on the session out of band.</summary>
    public ControlPlaneClient CreateSecondClient() =>
        new(ControlPlane.CreateClient(), new ConfiguredAccessTokenProvider(
            BearerTestAuthHandler.Token("oid-analyst", "analyst@fiaumalta.org", "device-1", "Mina.Analyst")));

    public async ValueTask DisposeAsync()
    {
        if (_proxy is not null)
        {
            await _proxy.DisposeAsync();
        }

        await Sessions.DisposeAsync();
        HttpClient.Dispose();
        ControlPlane.Dispose();
        await Egress.DisposeAsync();
        await Target.DisposeAsync();
        _serverCertificate.Dispose();
        _caPublic.Dispose();
        _ca.Dispose();
    }
}
