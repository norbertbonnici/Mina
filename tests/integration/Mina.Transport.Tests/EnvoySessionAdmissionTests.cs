using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Mina.ControlPlane.Pki;
using Mina.TestSupport;
using Xunit;

namespace Mina.Transport.Tests;

/// <summary>
/// M4-11 against a real Envoy: a valid certificate is necessary to open a tunnel and, since this
/// change, no longer sufficient. The node consults the sidecar for every tunnel and admits only
/// sessions the control plane currently lists — and when the sidecar does not answer, it admits
/// nothing. These are the tests that make "fail closed" a measured property rather than a
/// configuration comment.
/// </summary>
public sealed class EnvoySessionAdmissionTests
{
    private const string ServerName = "egress.local";
    private static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;

    [SkippableFact]
    public async Task A_session_the_control_plane_no_longer_lists_is_refused_within_one_refresh()
    {
        var envoyPath = EnvoyProcess.LocateBinary();
        Skip.If(envoyPath is null, "Set MINA_ENVOY to an Envoy binary to run the interop test.");

        using var ca = CertificateAuthority.Create("Mina Admission CA", Now.AddMinutes(-5), TimeSpan.FromDays(1));
        var work = Directory.CreateTempSubdirectory("mina-envoy");
        await using var admission = await SidecarAdmissionHost.StartAsync(EnvoyProcess.AuthzSocketPathFor(work));
        await using var envoy = await EnvoyProcess.StartAsync(envoyPath!, ca, ServerName, workingDirectory: work);
        await using var target = new TcpEchoServer();

        var sessionId = Guid.NewGuid();
        using var cert = ca.IssueClientCertificate(
            "mina-session-adm", $"mina:session:{sessionId}", Now.AddMinutes(-5), TimeSpan.FromMinutes(60));

        // Control leg: listed, so admitted.
        admission.Admit(sessionId);
        Assert.Equal(200, await ConnectStatusAsync(envoy, ca, cert, target.Port));

        // Revoked at the control plane, refreshed at the node. Same certificate, still valid for
        // another 55 minutes — and refused.
        admission.RevokeAll();
        Assert.Equal(403, await ConnectStatusAsync(envoy, ca, cert, target.Port));

        // Recorded at the node with the reason, so a refused attempt is visible in telemetry.
        var logged = await WaitForLogLineAsync(envoy.AccessLogPath, "ext_authz_denied");
        Assert.Contains("\"response_code\":403", logged, StringComparison.Ordinal);
        Assert.Contains($"mina:session:{sessionId}", logged, StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task A_valid_certificate_for_a_session_the_node_has_never_heard_of_is_refused()
    {
        // The stolen-or-forged-elsewhere case, and the one D-14 documented as unmitigated: a
        // certificate that chains correctly but names a session this region does not serve.
        var envoyPath = EnvoyProcess.LocateBinary();
        Skip.If(envoyPath is null, "Set MINA_ENVOY to an Envoy binary to run the interop test.");

        using var ca = CertificateAuthority.Create("Mina Admission CA", Now.AddMinutes(-5), TimeSpan.FromDays(1));
        var work = Directory.CreateTempSubdirectory("mina-envoy");
        await using var admission = await SidecarAdmissionHost.StartAsync(EnvoyProcess.AuthzSocketPathFor(work));
        await using var envoy = await EnvoyProcess.StartAsync(envoyPath!, ca, ServerName, workingDirectory: work);
        await using var target = new TcpEchoServer();

        admission.Admit(Guid.NewGuid());   // some other session
        using var cert = ca.IssueClientCertificate(
            "mina-session-other", $"mina:session:{Guid.NewGuid()}", Now.AddMinutes(-5), TimeSpan.FromMinutes(60));

        Assert.Equal(403, await ConnectStatusAsync(envoy, ca, cert, target.Port));
    }

    [SkippableFact]
    public async Task With_no_sidecar_answering_the_node_admits_nothing()
    {
        // Fail closed. Nothing listens on the admission socket; a valid certificate for a session
        // that would have been admitted gets no tunnel, and the reason is recorded as an error
        // rather than a refusal so an operator can tell a failing node from a revoked session.
        var envoyPath = EnvoyProcess.LocateBinary();
        Skip.If(envoyPath is null, "Set MINA_ENVOY to an Envoy binary to run the interop test.");

        using var ca = CertificateAuthority.Create("Mina Admission CA", Now.AddMinutes(-5), TimeSpan.FromDays(1));
        await using var envoy = await EnvoyProcess.StartAsync(envoyPath!, ca, ServerName);
        await using var target = new TcpEchoServer();
        using var cert = ca.IssueClientCertificate(
            "mina-session-nosidecar", $"mina:session:{Guid.NewGuid()}", Now.AddMinutes(-5), TimeSpan.FromMinutes(60));

        Assert.Equal(503, await ConnectStatusAsync(envoy, ca, cert, target.Port));

        var logged = await WaitForLogLineAsync(envoy.AccessLogPath, "ext_authz_error");
        Assert.Contains("\"response_code\":503", logged, StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task The_fail_closed_test_would_notice_if_the_node_failed_open()
    {
        // The meta-test. Same probe, same absent sidecar, failure_mode_allow rewritten to true in
        // the copy Envoy runs: the tunnel opens. If it did not, the test above would be passing for
        // some reason other than the line it is about, and would keep passing after that line
        // changed in the real file.
        var envoyPath = EnvoyProcess.LocateBinary();
        Skip.If(envoyPath is null, "Set MINA_ENVOY to an Envoy binary to run the interop test.");

        using var ca = CertificateAuthority.Create("Mina Admission CA", Now.AddMinutes(-5), TimeSpan.FromDays(1));
        await using var envoy = await EnvoyProcess.StartAsync(envoyPath!, ca, ServerName, failureModeAllow: true);
        await using var target = new TcpEchoServer();
        using var cert = ca.IssueClientCertificate(
            "mina-session-failopen", $"mina:session:{Guid.NewGuid()}", Now.AddMinutes(-5), TimeSpan.FromMinutes(60));

        Assert.Equal(200, await ConnectStatusAsync(envoy, ca, cert, target.Port));
    }

    [SkippableFact]
    public async Task A_client_cannot_assert_a_session_by_sending_the_forwarded_certificate_header_itself()
    {
        // SANITIZE_SET: whatever a client sends under x-forwarded-client-cert is discarded before
        // Envoy sets it from the certificate it verified. A certificate for session B carrying a
        // header claiming session A is session B, and B is not listed.
        var envoyPath = EnvoyProcess.LocateBinary();
        Skip.If(envoyPath is null, "Set MINA_ENVOY to an Envoy binary to run the interop test.");

        using var ca = CertificateAuthority.Create("Mina Admission CA", Now.AddMinutes(-5), TimeSpan.FromDays(1));
        var work = Directory.CreateTempSubdirectory("mina-envoy");
        await using var admission = await SidecarAdmissionHost.StartAsync(EnvoyProcess.AuthzSocketPathFor(work));
        await using var envoy = await EnvoyProcess.StartAsync(envoyPath!, ca, ServerName, workingDirectory: work);
        await using var target = new TcpEchoServer();

        var admitted = Guid.NewGuid();
        admission.Admit(admitted);
        using var certForOther = ca.IssueClientCertificate(
            "mina-session-spoof", $"mina:session:{Guid.NewGuid()}", Now.AddMinutes(-5), TimeSpan.FromMinutes(60));

        var status = await ConnectStatusAsync(
            envoy, ca, certForOther, target.Port,
            extraHeader: $"x-forwarded-client-cert: Hash=0;URI=mina:session:{admitted}");

        Assert.Equal(403, status);
    }

    [SkippableFact]
    public async Task The_health_listener_reflects_whether_the_sidecar_is_actually_healthy()
    {
        // The load balancer probes this, not the tunnel port (M4-11) — specifically because a node
        // can keep accepting TCP on the tunnel port while its admission path is dead. A codec
        // mismatch between the active health check and the sidecar's HTTP/2-only socket once left
        // this permanently 503 even with a perfectly healthy sidecar; found by curling the stack
        // interactively, not by any assertion, because every other test here talks to the sidecar
        // directly over gRPC and never went through Envoy's own active health check at all.
        var envoyPath = EnvoyProcess.LocateBinary();
        Skip.If(envoyPath is null, "Set MINA_ENVOY to an Envoy binary to run the interop test.");

        using var ca = CertificateAuthority.Create("Mina Health CA", Now.AddMinutes(-5), TimeSpan.FromDays(1));
        var work = Directory.CreateTempSubdirectory("mina-envoy");
        await using var admission = await SidecarAdmissionHost.StartAsync(EnvoyProcess.AuthzSocketPathFor(work));
        // A real sidecar's refresh loop calls Update() on every tick, including a tick that finds
        // zero live sessions — that is what makes /healthz report healthy at all. The bare test
        // host does not run that loop, so the test drives it once itself to reach the same state a
        // freshly booted, otherwise-idle sidecar would be in.
        admission.RevokeAll();
        await using var envoy = await EnvoyProcess.StartAsync(envoyPath!, ca, ServerName, workingDirectory: work);

        Assert.True(
            await WaitForHealthAsync(envoy.HealthPort, expectHealthy: true),
            "the health listener never reported healthy with a live sidecar answering");
    }

    [Fact]
    public void The_shipped_config_caps_open_tunnel_duration_at_the_owners_chosen_60_minutes()
    {
        // Not gated on MINA_ENVOY: this is a plain text assertion on the committed file, not a
        // behavioural test, and it exists to catch an edit to the number itself. D-19a (2026-09-04)
        // is the owner's deliberate choice of 60 min over a tighter cap; a change here is a decision
        // to make again, not a refactor.
        var config = File.ReadAllText(EnvoyProcess.LocateConfig());
        Assert.Contains("max_stream_duration: 3600s", config, StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task An_admitted_tunnel_is_force_closed_once_the_connection_duration_cap_elapses()
    {
        // M4-11 remaining / D-19a: ext_authz only ever runs at CONNECT time, so without a duration
        // cap a tunnel stays open regardless of what happens to its session afterwards. This proves
        // the cap itself resets an open tunnel's stream on age alone — deliberately with the session
        // still admitted throughout, because that is exactly the property THREAT_MODEL residual risk
        // 6 says admission cannot provide: the cap has to close the tunnel even though nothing about
        // the session changed. First written against max_connection_duration, which turned out not
        // to work at all here: Envoy logs "max connection duration reached" on schedule but then
        // waits for the (never-ending) tunnel stream to finish before closing anything, proving
        // nothing. max_stream_duration is what actually resets an active stream on age.
        var envoyPath = EnvoyProcess.LocateBinary();
        Skip.If(envoyPath is null, "Set MINA_ENVOY to an Envoy binary to run the interop test.");

        using var ca = CertificateAuthority.Create("Mina Admission CA", Now.AddMinutes(-5), TimeSpan.FromDays(1));
        var work = Directory.CreateTempSubdirectory("mina-envoy");
        await using var admission = await SidecarAdmissionHost.StartAsync(EnvoyProcess.AuthzSocketPathFor(work));
        await using var envoy = await EnvoyProcess.StartAsync(
            envoyPath!, ca, ServerName, workingDirectory: work,
            maxStreamDurationOverride: TimeSpan.FromSeconds(2));
        await using var target = new TcpEchoServer();

        var sessionId = Guid.NewGuid();
        using var cert = ca.IssueClientCertificate(
            "mina-session-cap", $"mina:session:{sessionId}", Now.AddMinutes(-5), TimeSpan.FromMinutes(60));
        admission.Admit(sessionId);

        using var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
        using var connectTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        await socket.ConnectAsync("127.0.0.1", envoy.IngressPort, connectTimeout.Token);
        await using var network = new NetworkStream(socket, ownsSocket: false);
        await using var tls = new SslStream(network, leaveInnerStreamOpen: true);

        using var caPublic = ca.PublicCertificate;
        var options = new SslClientAuthenticationOptions
        {
            TargetHost = ServerName,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            ClientCertificates = [cert],
            CertificateChainPolicy = new X509ChainPolicy
            {
                TrustMode = X509ChainTrustMode.CustomRootTrust,
                RevocationMode = X509RevocationMode.NoCheck,
            },
        };
        options.CertificateChainPolicy.CustomTrustStore.Add(caPublic);
        await tls.AuthenticateAsClientAsync(options, connectTimeout.Token);

        var request = new StringBuilder()
            .Append("CONNECT 127.0.0.1:").Append(target.Port).Append(" HTTP/1.1\r\n")
            .Append("Host: 127.0.0.1:").Append(target.Port).Append("\r\n\r\n");
        await tls.WriteAsync(Encoding.ASCII.GetBytes(request.ToString()), connectTimeout.Token);

        var connectResponse = new byte[256];
        var connectRead = await tls.ReadAsync(connectResponse, connectTimeout.Token);
        var connectLine = Encoding.ASCII.GetString(connectResponse, 0, connectRead);
        Assert.StartsWith("HTTP/1.1 200", connectLine, StringComparison.Ordinal);

        // The tunnel is admitted and open, and the session is never revoked. Only age can close it
        // now. Poll well past the 2 s cap (plus Envoy's own drain grace) for the connection to die.
        using var closeTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var buffer = new byte[256];
        var closed = false;
        try
        {
            while (!closeTimeout.IsCancellationRequested)
            {
                var read = await tls.ReadAsync(buffer, closeTimeout.Token);
                if (read == 0)
                {
                    closed = true;
                    break;
                }
            }
        }
        catch (Exception ex) when (ex is IOException or SocketException)
        {
            closed = true;
        }
        catch (OperationCanceledException) when (closeTimeout.IsCancellationRequested)
        {
            // The 20 s poll window ran out without the connection dying — closed stays false and
            // the assertion below reports it plainly instead of surfacing this as a raw timeout.
        }

        Assert.True(closed, "the tunnel was still open past its max_stream_duration cap");

        // The session was admitted the whole time; a fresh CONNECT proves the node, not the
        // session, is what changed.
        Assert.Equal(200, await ConnectStatusAsync(envoy, ca, cert, target.Port));
    }

    [SkippableFact]
    public async Task The_health_listener_reports_unhealthy_with_no_sidecar_at_all()
    {
        var envoyPath = EnvoyProcess.LocateBinary();
        Skip.If(envoyPath is null, "Set MINA_ENVOY to an Envoy binary to run the interop test.");

        using var ca = CertificateAuthority.Create("Mina Health CA", Now.AddMinutes(-5), TimeSpan.FromDays(1));
        await using var envoy = await EnvoyProcess.StartAsync(envoyPath!, ca, ServerName);

        Assert.True(
            await WaitForHealthAsync(envoy.HealthPort, expectHealthy: false),
            "the health listener reported healthy with no sidecar reachable at all");
    }

    private static async Task<bool> WaitForHealthAsync(int healthPort, bool expectHealthy)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(2) };
        for (var attempt = 0; attempt < 30; attempt++)
        {
            try
            {
                using var response = await http.GetAsync(new Uri($"http://127.0.0.1:{healthPort}/healthz"));
                var healthy = response.StatusCode == System.Net.HttpStatusCode.OK;
                if (healthy == expectHealthy)
                {
                    return true;
                }
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
            {
            }

            await Task.Delay(500);
        }

        return false;
    }

    /// <summary>
    /// One CONNECT to a local target through the real mTLS ingress; returns the HTTP status Envoy
    /// answered with, or null if the connection died without one.
    /// </summary>
    private static async Task<int?> ConnectStatusAsync(
        EnvoyProcess envoy, CertificateAuthority authority, X509Certificate2 clientCertificate, int targetPort,
        string? extraHeader = null)
    {
        using var caPublic = authority.PublicCertificate;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));

        using var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
        await socket.ConnectAsync("127.0.0.1", envoy.IngressPort, timeout.Token);
        await using var network = new NetworkStream(socket, ownsSocket: false);
        await using var tls = new SslStream(network, leaveInnerStreamOpen: true);

        var options = new SslClientAuthenticationOptions
        {
            TargetHost = ServerName,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            ClientCertificates = [clientCertificate],
            CertificateChainPolicy = new X509ChainPolicy
            {
                TrustMode = X509ChainTrustMode.CustomRootTrust,
                RevocationMode = X509RevocationMode.NoCheck,
            },
        };
        options.CertificateChainPolicy.CustomTrustStore.Add(caPublic);

        try
        {
            await tls.AuthenticateAsClientAsync(options, timeout.Token);

            var request = new StringBuilder()
                .Append("CONNECT 127.0.0.1:").Append(targetPort).Append(" HTTP/1.1\r\n")
                .Append("Host: 127.0.0.1:").Append(targetPort).Append("\r\n");
            if (extraHeader is not null)
            {
                request.Append(extraHeader).Append("\r\n");
            }

            request.Append("\r\n");
            await tls.WriteAsync(Encoding.ASCII.GetBytes(request.ToString()), timeout.Token);

            var buffer = new byte[256];
            var read = await tls.ReadAsync(buffer, timeout.Token);
            if (read == 0)
            {
                return null;
            }

            var line = Encoding.ASCII.GetString(buffer, 0, read);
            Assert.StartsWith("HTTP/1.1 ", line, StringComparison.Ordinal);
            return int.Parse(line.AsSpan(9, 3), System.Globalization.CultureInfo.InvariantCulture);
        }
        catch (Exception ex) when (ex is AuthenticationException or IOException or SocketException)
        {
            return null;
        }
    }

    private static async Task<string> WaitForLogLineAsync(string path, string mustContain)
    {
        // Envoy buffers file access logs and flushes on an interval (seconds), so a line written
        // late in a short test can lag the read. Wait well past that interval before giving up.
        for (var attempt = 0; attempt < 150; attempt++)
        {
            if (File.Exists(path))
            {
                await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var reader = new StreamReader(stream);
                var text = await reader.ReadToEndAsync();
                if (text.Contains(mustContain, StringComparison.Ordinal))
                {
                    return text;
                }
            }

            await Task.Delay(100);
        }

        return File.Exists(path) ? await File.ReadAllTextAsync(path) : string.Empty;
    }
}
