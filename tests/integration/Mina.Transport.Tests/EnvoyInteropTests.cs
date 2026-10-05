using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Mina.ControlPlane.Pki;
using Mina.EgressNode.Sidecar;
using Mina.EndpointAgent.Proxy;
using Mina.TestSupport;
using Xunit;

namespace Mina.Transport.Tests;

/// <summary>
/// True interop proof: the real .NET agent (loopback proxy + mTLS tunnel client) talking to a
/// real Envoy process running the committed egress config. Skipped unless MINA_ENVOY points at
/// an Envoy binary, so CI without Envoy stays green; run locally with:
///   MINA_ENVOY=/path/to/envoy dotnet test tests/integration/Mina.Transport.Tests
/// </summary>
public sealed class EnvoyInteropTests
{
    private const string ServerName = "egress.local";
    private static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;

    [SkippableFact]
    public async Task Agent_tunnels_through_real_envoy_and_hostname_is_logged()
    {
        var envoyPath = EnvoyProcess.LocateBinary();
        Skip.If(envoyPath is null, "Set MINA_ENVOY to an Envoy binary to run the interop test.");

        using var ca = CertificateAuthority.Create("Mina Interop CA", Now.AddMinutes(-5), TimeSpan.FromDays(1));
        using var caPublic = ca.PublicCertificate;

        // Since M4-11 Envoy admits nothing the sidecar does not list, so the sidecar's admission
        // listener runs here too and the session is listed before the tunnel is attempted.
        var work = Directory.CreateTempSubdirectory("mina-envoy");
        await using var admission = await SidecarAdmissionHost.StartAsync(EnvoyProcess.AuthzSocketPathFor(work));
        await using var envoy = await EnvoyProcess.StartAsync(envoyPath!, ca, ServerName, workingDirectory: work);
        await using var target = new TcpEchoServer();

        var sessionId = Guid.NewGuid();
        admission.Admit(sessionId);
        using var sessionCert = ca.IssueClientCertificate(
            "mina-session-interop", $"mina:session:{sessionId}", Now.AddMinutes(-5), TimeSpan.FromMinutes(60));
        var clientPfx = sessionCert.Export(X509ContentType.Pkcs12);

        var factory = new MtlsTunnelConnectionFactory(
            new EgressEndpoint("127.0.0.1", envoy.IngressPort, ServerName),
            () => X509CertificateLoader.LoadPkcs12(clientPfx, password: null),
            caPublic);

        await using var proxy = new LoopbackConnectProxy(
            factory, new LoopbackPeerAuthorizer(), NullLogger<LoopbackConnectProxy>.Instance);
        proxy.Start();

        var echoed = await BrowserRoundTripAsync(
            proxy.Endpoint!, new ConnectTarget("127.0.0.1", target.Port), "hello-through-envoy");
        Assert.Equal("hello-through-envoy", echoed);

        // Hostname telemetry (ADR-0002 Option 1) is emitted by Envoy without TLS interception.
        var authority = $"127.0.0.1:{target.Port}";
        var logged = await WaitForLogLineAsync(envoy.AccessLogPath, authority);
        Assert.Contains("mina.hostname.v1", logged, StringComparison.Ordinal);
        Assert.Contains(authority, logged, StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task A_suppressed_sessions_destination_never_reaches_envoys_access_log()
    {
        // The residual risk SECURITY_REVIEW_2026-09-01 recorded: Envoy logged every CONNECT
        // authority, so a suppressed session's destinations sat on the node's disk until the
        // sidecar read and dropped them. Now the sidecar flags the session at admission and Envoy
        // selects a redacted log line for its tunnels. This proves it against the real binary and
        // the committed config: the tunnel works, the line is written, and the authority is nowhere
        // in the file.
        var envoyPath = EnvoyProcess.LocateBinary();
        Skip.If(envoyPath is null, "Set MINA_ENVOY to an Envoy binary to run the interop test.");

        using var ca = CertificateAuthority.Create("Mina Interop CA", Now.AddMinutes(-5), TimeSpan.FromDays(1));
        using var caPublic = ca.PublicCertificate;

        var work = Directory.CreateTempSubdirectory("mina-envoy");
        await using var admission = await SidecarAdmissionHost.StartAsync(EnvoyProcess.AuthzSocketPathFor(work));
        await using var envoy = await EnvoyProcess.StartAsync(envoyPath!, ca, ServerName, workingDirectory: work);
        await using var target = new TcpEchoServer();

        var sessionId = Guid.NewGuid();
        admission.AdmitSuppressed(sessionId);
        using var sessionCert = ca.IssueClientCertificate(
            "mina-session-suppressed", $"mina:session:{sessionId}", Now.AddMinutes(-5), TimeSpan.FromMinutes(60));
        var clientPfx = sessionCert.Export(X509ContentType.Pkcs12);

        var factory = new MtlsTunnelConnectionFactory(
            new EgressEndpoint("127.0.0.1", envoy.IngressPort, ServerName),
            () => X509CertificateLoader.LoadPkcs12(clientPfx, password: null),
            caPublic);

        await using var proxy = new LoopbackConnectProxy(
            factory, new LoopbackPeerAuthorizer(), NullLogger<LoopbackConnectProxy>.Instance);
        proxy.Start();

        // Suppression is about what is recorded, not whether the analyst may browse.
        var echoed = await BrowserRoundTripAsync(
            proxy.Endpoint!, new ConnectTarget("127.0.0.1", target.Port), "hello-under-suppression");
        Assert.Equal("hello-under-suppression", echoed);

        // One line for the tunnel, attributed to the session, flagged, and with no authority.
        var logged = await WaitForLogLineAsync(envoy.AccessLogPath, $"mina:session:{sessionId}");
        var lines = logged.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        var line = Assert.Single(lines, l => l.Contains($"mina:session:{sessionId}", StringComparison.Ordinal));
        Assert.Contains("\"schema\":\"mina.hostname.v1\"", line, StringComparison.Ordinal);
        Assert.Contains("\"suppressed\":\"true\"", line, StringComparison.Ordinal);
        Assert.Contains("\"response_code\":200", line, StringComparison.Ordinal);
        Assert.DoesNotContain("authority", line, StringComparison.Ordinal);

        // And the destination is absent from the whole file, not merely from that line.
        var authority = $"127.0.0.1:{target.Port}";
        Assert.DoesNotContain(authority, logged, StringComparison.Ordinal);

        // The sidecar's parser turns that line into a counts-only item: the shipped shape is the
        // same one the control plane already aggregates for a suppressed session.
        var entry = AccessLogParser.TryParse(line);
        Assert.NotNull(entry);
        Assert.Equal(sessionId, entry.SessionId);
        Assert.Null(entry.Hostname);
    }

    [SkippableFact]
    public async Task An_unsuppressed_sessions_line_carries_the_authority_and_no_suppressed_flag()
    {
        // The control leg for the test above, and a regression guard on the inverted filter: an
        // ordinary session must still be logged in full by exactly one logger, not twice and not
        // redacted.
        var envoyPath = EnvoyProcess.LocateBinary();
        Skip.If(envoyPath is null, "Set MINA_ENVOY to an Envoy binary to run the interop test.");

        using var ca = CertificateAuthority.Create("Mina Interop CA", Now.AddMinutes(-5), TimeSpan.FromDays(1));
        using var caPublic = ca.PublicCertificate;

        var work = Directory.CreateTempSubdirectory("mina-envoy");
        await using var admission = await SidecarAdmissionHost.StartAsync(EnvoyProcess.AuthzSocketPathFor(work));
        await using var envoy = await EnvoyProcess.StartAsync(envoyPath!, ca, ServerName, workingDirectory: work);
        await using var target = new TcpEchoServer();

        var sessionId = Guid.NewGuid();
        admission.Admit(sessionId);
        using var sessionCert = ca.IssueClientCertificate(
            "mina-session-plain", $"mina:session:{sessionId}", Now.AddMinutes(-5), TimeSpan.FromMinutes(60));
        var clientPfx = sessionCert.Export(X509ContentType.Pkcs12);

        var factory = new MtlsTunnelConnectionFactory(
            new EgressEndpoint("127.0.0.1", envoy.IngressPort, ServerName),
            () => X509CertificateLoader.LoadPkcs12(clientPfx, password: null),
            caPublic);
        await using var proxy = new LoopbackConnectProxy(
            factory, new LoopbackPeerAuthorizer(), NullLogger<LoopbackConnectProxy>.Instance);
        proxy.Start();

        Assert.Equal("plain", await BrowserRoundTripAsync(
            proxy.Endpoint!, new ConnectTarget("127.0.0.1", target.Port), "plain"));

        var authority = $"127.0.0.1:{target.Port}";
        var logged = await WaitForLogLineAsync(envoy.AccessLogPath, authority);
        var lines = logged.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        var line = Assert.Single(lines, l => l.Contains($"mina:session:{sessionId}", StringComparison.Ordinal));
        Assert.Contains($"\"authority\":\"{authority}\"", line, StringComparison.Ordinal);
        Assert.DoesNotContain("suppressed", line, StringComparison.Ordinal);
    }

    [SkippableTheory]
    [InlineData("169.254.169.254", 80)]   // Azure IMDS: managed-identity tokens for this node's Key Vault
    [InlineData("10.1.2.3", 443)]         // corporate/private space (SR-004)
    [InlineData("192.168.1.1", 443)]
    [InlineData("172.20.0.5", 443)]
    [InlineData("localhost", 9901)]       // the node's own services by name
    [InlineData("168.63.129.16", 80)]     // Azure platform address: WireServer goal state
    [InlineData("168.63.129.16", 32526)]  // ...and the host GA plugin
    // Zero-padded octets are read as decimal by c-ares, so this is the same address by another
    // spelling. The deny has to match what will actually be resolved, not one canonical form.
    [InlineData("168.063.129.016", 80)]
    // Any resolver port, by name. This is the one destination class the socket-level rule cannot
    // refuse — the nftables exception that lets Envoy's own resolver reach 168.63.129.16:53 is
    // scoped by uid, and a proxied tunnel is that same uid — so it has to be refused here, before
    // resolution. Nothing legitimate CONNECTs to a resolver: DNS is done at the node by design.
    [InlineData("resolver.example.test", 53)]
    [InlineData("resolver.example.test", 853)]   // DNS-over-TLS is the same tunnel, renumbered
    [InlineData("resolver.example.test", 5353)]  // ...as is mDNS
    // The same zero-padding question as 168.063.129.016, asked of the ranges that were already
    // here. No loopback row: the harness narrows the 127 deny to 127.128 so tests can use
    // 127.0.0.1, so a padded loopback authority is legitimately allowed under the test config.
    [InlineData("010.1.2.3", 443)]
    [InlineData("0192.0168.1.1", 443)]
    [InlineData("0169.0254.169.254", 80)]
    public async Task Envoy_refuses_to_connect_to_private_and_link_local_destinations(string host, int port)
    {
        var envoyPath = EnvoyProcess.LocateBinary();
        Skip.If(envoyPath is null, "Set MINA_ENVOY to an Envoy binary to run the interop test.");

        using var ca = CertificateAuthority.Create("Mina Interop CA", Now.AddMinutes(-5), TimeSpan.FromDays(1));
        using var caPublic = ca.PublicCertificate;

        // The session is admitted, deliberately: the refusal under test must come from the
        // destination policy, and with the session unknown to the sidecar it would come from
        // admission first and this test would pass without the RBAC filter existing at all.
        var work = Directory.CreateTempSubdirectory("mina-envoy");
        await using var admission = await SidecarAdmissionHost.StartAsync(EnvoyProcess.AuthzSocketPathFor(work));
        await using var envoy = await EnvoyProcess.StartAsync(envoyPath!, ca, ServerName, workingDirectory: work);

        var sessionId = Guid.NewGuid();
        admission.Admit(sessionId);
        using var sessionCert = ca.IssueClientCertificate(
            "mina-session-interop", $"mina:session:{sessionId}", Now.AddMinutes(-5), TimeSpan.FromMinutes(60));
        var clientPfx = sessionCert.Export(X509ContentType.Pkcs12);

        var factory = new MtlsTunnelConnectionFactory(
            new EgressEndpoint("127.0.0.1", envoy.IngressPort, ServerName),
            () => X509CertificateLoader.LoadPkcs12(clientPfx, password: null),
            caPublic);

        await using var proxy = new LoopbackConnectProxy(
            factory, new LoopbackPeerAuthorizer(), NullLogger<LoopbackConnectProxy>.Instance);
        proxy.Start();

        // A valid, live session certificate is not authority to reach anywhere the node can reach.
        // Egress is for the public internet; the node's own loopback services and the IMDS endpoint
        // that issues its Key Vault tokens are not part of that.
        using var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
        await socket.ConnectAsync(proxy.Endpoint!);
        await using var stream = new NetworkStream(socket, ownsSocket: false);
        await stream.WriteAsync(HttpConnect.BuildConnectRequest(new ConnectTarget(host, port)));

        // Envoy answers 403; the agent has no direct fallback, so the browser gets a 502 and the
        // connection simply does not happen.
        var status = await HttpConnect.ReadResponseStatusAsync(stream, CancellationToken.None);
        Assert.Equal(502, status);

        // The refusal is recorded at the node, so an attempt on IMDS is visible rather than silent —
        // and attributed to the destination policy, not to admission.
        var logged = await WaitForLogLineAsync(envoy.AccessLogPath, $"{host}:{port}");
        Assert.Contains("\"response_code\":403", logged, StringComparison.Ordinal);
        Assert.Contains("rbac_access_denied", logged, StringComparison.Ordinal);
    }

    private static async Task<string> WaitForLogLineAsync(string path, string mustContain)
    {
        for (var attempt = 0; attempt < 50; attempt++)
        {
            if (File.Exists(path))
            {
                var text = await ReadAllTextSharedAsync(path);
                if (text.Contains(mustContain, StringComparison.Ordinal))
                {
                    return text;
                }
            }

            await Task.Delay(100);
        }

        return File.Exists(path) ? await ReadAllTextSharedAsync(path) : string.Empty;
    }

    private static async Task<string> ReadAllTextSharedAsync(string path)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var reader = new StreamReader(stream);
        return await reader.ReadToEndAsync();
    }

    private static async Task<string> BrowserRoundTripAsync(IPEndPoint proxy, ConnectTarget target, string payload)
    {
        using var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
        await socket.ConnectAsync(proxy);
        await using var stream = new NetworkStream(socket, ownsSocket: false);

        await stream.WriteAsync(HttpConnect.BuildConnectRequest(target));
        Assert.Equal(200, await HttpConnect.ReadResponseStatusAsync(stream, CancellationToken.None));

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
}
