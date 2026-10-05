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
/// AC-016 and the open-proxy threat rest on one line of the egress configuration —
/// <c>require_client_certificate: true</c> in <c>egress-node/envoy/envoy-bootstrap.yaml</c>. Nothing
/// read that line: the in-process stand-in hardcodes the equivalent in C#, and the agent always
/// presents a certificate, so no test could express a scanner arriving with none. Deleting the line
/// left <c>envoy --mode validate</c> perfectly happy.
/// </summary>
/// <remarks>
/// The assertion is deliberately about the outcome, not about where the failure surfaces. Under
/// TLS 1.3 the server finishes its side of the handshake before it has judged the client, so
/// <c>AuthenticateAsClientAsync</c> can return successfully and the refusal arrives as an alert on
/// the first read — while under TLS 1.2 it throws during the handshake. A test that asserted
/// "throws AuthenticationException" would therefore be testing the negotiated protocol version, not
/// client authentication. What must be true either way is that no tunnel is ever established.
/// </remarks>
public sealed class EnvoyClientAuthTests
{
    private const string ServerName = "egress.local";
    private static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;

    private enum Outcome
    {
        /// <summary>The proxy answered a CONNECT: the tunnel was established.</summary>
        Tunnelled,

        /// <summary>No HTTP response ever arrived, wherever the connection died.</summary>
        Refused,
    }

    [SkippableFact]
    public async Task Real_envoy_refuses_a_client_that_presents_no_certificate()
    {
        var envoyPath = EnvoyProcess.LocateBinary();
        Skip.If(envoyPath is null, "Set MINA_ENVOY to an Envoy binary to run the interop test.");

        using var ca = CertificateAuthority.Create("Mina ClientAuth CA", Now.AddMinutes(-5), TimeSpan.FromDays(1));
        var work = Directory.CreateTempSubdirectory("mina-envoy");
        await using var admission = await SidecarAdmissionHost.StartAsync(EnvoyProcess.AuthzSocketPathFor(work));
        await using var envoy = await EnvoyProcess.StartAsync(envoyPath!, ca, ServerName, workingDirectory: work);

        // Control leg first. Without it, a refusal would prove only that something is broken —
        // a wrong port, a bad CA, an Envoy that never started, a sidecar that admits nothing.
        var sessionId = Guid.NewGuid();
        admission.Admit(sessionId);
        using var sessionCert = ca.IssueClientCertificate(
            "mina-session-clientauth", $"mina:session:{sessionId}", Now.AddMinutes(-5), TimeSpan.FromMinutes(60));
        Assert.Equal(Outcome.Tunnelled, await ProbeAsync(envoy, ca, sessionCert));

        // The scanner: same endpoint, no client certificate.
        Assert.Equal(Outcome.Refused, await ProbeAsync(envoy, ca, clientCertificate: null));
    }

    [SkippableFact]
    public async Task Real_envoy_refuses_an_expired_session_certificate_that_otherwise_chains_and_is_admitted()
    {
        // M2-6: an expired-but-otherwise-valid Mina-issued certificate against the relying party
        // that matters most. The session is deliberately *listed* at the sidecar, so the only thing
        // standing between this certificate and a tunnel is Envoy's own validity check — a refusal
        // here cannot be admission doing the work. Revocation in Mina works by declining to renew
        // (D-14/D-19), so "expired certificates are refused at the node" is the property the whole
        // lease model rests on.
        var envoyPath = EnvoyProcess.LocateBinary();
        Skip.If(envoyPath is null, "Set MINA_ENVOY to an Envoy binary to run the interop test.");

        // The CA predates the leaf comfortably, so the leaf's notBefore is not clamped forward.
        using var ca = CertificateAuthority.Create("Mina ClientAuth CA", Now.AddHours(-3), TimeSpan.FromDays(1));
        var work = Directory.CreateTempSubdirectory("mina-envoy");
        await using var admission = await SidecarAdmissionHost.StartAsync(EnvoyProcess.AuthzSocketPathFor(work));
        await using var envoy = await EnvoyProcess.StartAsync(envoyPath!, ca, ServerName, workingDirectory: work);

        var sessionId = Guid.NewGuid();
        admission.Admit(sessionId);

        // Control leg: a current certificate for the same admitted session tunnels.
        using var current = ca.IssueClientCertificate(
            "mina-session-current", $"mina:session:{sessionId}", Now.AddMinutes(-5), TimeSpan.FromMinutes(60));
        Assert.Equal(Outcome.Tunnelled, await ProbeAsync(envoy, ca, current));

        // Valid from two hours ago for one hour: expired an hour ago, chains, correct EKU, listed.
        using var expired = ca.IssueClientCertificate(
            "mina-session-expired", $"mina:session:{sessionId}", Now.AddHours(-2), TimeSpan.FromHours(1));
        Assert.True(expired.NotAfter.ToUniversalTime() < DateTime.UtcNow, "test setup: the certificate must already be expired");

        Assert.Equal(Outcome.Refused, await ProbeAsync(envoy, ca, expired));
    }

    [SkippableFact]
    public async Task The_client_authentication_test_would_notice_if_the_requirement_were_removed()
    {
        // A guard that cannot fail guards nothing. This runs the same probe against the same
        // committed config with require_client_certificate rewritten to false — if the uncertificated
        // client still could not tunnel, the test above would be passing for some other reason and
        // would keep passing after someone removed the requirement.
        var envoyPath = EnvoyProcess.LocateBinary();
        Skip.If(envoyPath is null, "Set MINA_ENVOY to an Envoy binary to run the interop test.");

        using var ca = CertificateAuthority.Create("Mina ClientAuth CA", Now.AddMinutes(-5), TimeSpan.FromDays(1));
        await using var envoy = await EnvoyProcess.StartAsync(
            envoyPath!, ca, ServerName, requireClientCertificate: false);

        // No admission host: with no certificate there is no session to admit, so the answer here
        // is a 403 from admission rather than a tunnel — which is still an HTTP response, which is
        // what "Tunnelled" means in this file: the TLS layer let the client through.
        Assert.Equal(Outcome.Tunnelled, await ProbeAsync(envoy, ca, clientCertificate: null));
    }

    /// <summary>
    /// Attempts one CONNECT and reports only whether a tunnel came out of it. Every failure mode of
    /// a rejected connection — an alert during the handshake, an alert on the first read, a reset,
    /// an EOF — is the same answer.
    /// </summary>
    private static async Task<Outcome> ProbeAsync(
        EnvoyProcess envoy, CertificateAuthority authority, X509Certificate2? clientCertificate)
    {
        using var caPublic = authority.PublicCertificate;
        var trust = new X509Certificate2Collection(caPublic);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));

        using var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
        await socket.ConnectAsync("127.0.0.1", envoy.IngressPort, timeout.Token);
        await using var network = new NetworkStream(socket, ownsSocket: false);
        await using var tls = new SslStream(network, leaveInnerStreamOpen: true);

        var options = new SslClientAuthenticationOptions
        {
            TargetHost = ServerName,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            CertificateChainPolicy = new X509ChainPolicy
            {
                TrustMode = X509ChainTrustMode.CustomRootTrust,
                RevocationMode = X509RevocationMode.NoCheck,
            },
        };
        options.CertificateChainPolicy.CustomTrustStore.AddRange(trust);
        if (clientCertificate is not null)
        {
            options.ClientCertificates = [clientCertificate];
        }

        try
        {
            await tls.AuthenticateAsClientAsync(options, timeout.Token);

            var request = Encoding.ASCII.GetBytes(
                $"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n");
            await tls.WriteAsync(request, timeout.Token);

            var buffer = new byte[64];
            var read = await tls.ReadAsync(buffer, timeout.Token);
            if (read == 0)
            {
                return Outcome.Refused;
            }

            var status = Encoding.ASCII.GetString(buffer, 0, read);
            Assert.StartsWith("HTTP/1.1", status, StringComparison.Ordinal);
            return Outcome.Tunnelled;
        }
        catch (Exception ex) when (ex is AuthenticationException or IOException or SocketException)
        {
            // The enumerated ways a refused mTLS connection dies. Anything else is a bug in the
            // test and is deliberately allowed to propagate; a timeout fails the test rather than
            // counting as a refusal, because a hang is not proof of anything.
            return Outcome.Refused;
        }
    }
}
