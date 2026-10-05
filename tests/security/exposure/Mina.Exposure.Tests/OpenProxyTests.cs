using System.Diagnostics.CodeAnalysis;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Azure.Identity;
using Mina.ControlPlane.KeyVault;
using Mina.ControlPlane.Pki;
using Xunit;

namespace Mina.Exposure.Tests;

/// <summary>
/// AC-016 against a deployed stamp: the ingress address must not be usable as a proxy by anyone who
/// simply finds it. `EnvoyClientAuthTests` and `EnvoySessionAdmissionTests` already prove this
/// against a real Envoy in Docker, which is the right place to prove the *configuration* is sound.
/// What they cannot show is that the configuration reached the machine — that the node booted with
/// it, that the load balancer forwards to the port that has it, and that nothing else on the host
/// answers. This suite is the arriving scanner (TEST_STRATEGY §2, M1-7).
/// </summary>
/// <remarks>
/// Every assertion is a negative, so the suite opens with a positive control: the tunnel port must
/// answer TLS and demand a client certificate. Without that, a stopped node, a wrong address or a
/// firewall in front of the tester would produce a full set of passes.
/// </remarks>
public sealed class OpenProxyTests
{
    /// <summary>
    /// What came of one probe. Every way a refused connection can die — an alert during the
    /// handshake, an alert on the first read, a reset, an EOF — is the same answer, because the
    /// question is only ever "did this become a tunnel".
    /// </summary>
    private enum Outcome
    {
        /// <summary>A 2xx came back: the proxy opened a tunnel. This is the open-proxy finding.</summary>
        Tunnelled,

        /// <summary>The TLS layer refused the client, so no HTTP was ever spoken.</summary>
        RefusedAtTls,

        /// <summary>TLS succeeded and the proxy then declined to open a tunnel.</summary>
        RefusedAfterTls,
    }

    /// <summary>The outcome plus, when there was one, the status line that carried it.</summary>
    private readonly record struct Probe(Outcome Outcome, string? Status)
    {
        public bool Refused => Outcome != Outcome.Tunnelled;
    }

    [SkippableFact]
    public async Task The_tunnel_port_answers_and_demands_a_client_certificate()
    {
        // The control leg. It also pins two facts worth pinning: the node presents a certificate
        // issued by the internal CA (not a public one, not a self-signed leftover), and it names
        // the internal CA as the only issuer it will accept from a client.
        var ingress = Require(StampUnderTest.Ingress, StampUnderTest.IngressVariable);

        var (serverCertificate, acceptableIssuers) = await InspectTlsAsync(ingress);

        Assert.NotNull(serverCertificate);
        Assert.Equal("CN=Mina Internal CA", serverCertificate!.Issuer);
        Assert.Contains(acceptableIssuers, issuer => issuer.Contains("Mina Internal CA", StringComparison.Ordinal));
    }

    [SkippableFact]
    public async Task A_scanner_with_no_client_certificate_cannot_tunnel()
    {
        var ingress = Require(StampUnderTest.Ingress, StampUnderTest.IngressVariable);

        Assert.True((await ProbeAsync(ingress, clientCertificate: null)).Refused);
    }

    [SkippableFact]
    public async Task A_client_certificate_from_another_authority_cannot_tunnel()
    {
        // The certificate is valid, unexpired and carries the right extensions. The only thing
        // wrong with it is who signed it, which is the whole of what mTLS checks here.
        var ingress = Require(StampUnderTest.Ingress, StampUnderTest.IngressVariable);

        using var rogue = CertificateAuthority.Create(
            "Rogue CA", DateTimeOffset.UtcNow.AddMinutes(-5), TimeSpan.FromDays(1));
        using var forged = rogue.IssueClientCertificate(
            "mina-session-impostor",
            $"mina:session:{Guid.NewGuid():D}",
            DateTimeOffset.UtcNow.AddMinutes(-5),
            TimeSpan.FromMinutes(60));

        Assert.True((await ProbeAsync(ingress, forged)).Refused);
    }

    [SkippableFact]
    public async Task A_certificate_that_chains_to_the_real_ca_is_still_not_enough()
    {
        // D-19's central claim, live for the first time: a certificate chaining to the internal CA
        // is necessary but not sufficient, because the node also asks the control plane whether the
        // session is one it currently lists. This probe holds a certificate the live CA genuinely
        // signed -- issued here with the operator's own Key Vault rights, one sign operation,
        // nothing written to the vault -- for a session id the control plane has never heard of.
        //
        // If this ever returns Tunnelled, anyone who can obtain a certificate from the internal CA
        // has an open proxy, and node-side admission is not doing what M4-11 says it does.
        var ingress = Require(StampUnderTest.Ingress, StampUnderTest.IngressVariable);
        var vault = Require(StampUnderTest.VaultUri, StampUnderTest.VaultVariable);

        using var ca = await KeyVaultCertificateAuthority.LoadAsync(
            new KeyVaultCaOptions(new Uri(vault)), new DefaultAzureCredential());
        var strangerSession = Guid.NewGuid();
        using var chained = ca.IssueClientCertificate(
            $"mina-session-{strangerSession:D}",
            SessionCertificateIssuer.SessionUri(strangerSession),
            DateTimeOffset.UtcNow.AddMinutes(-5),
            TimeSpan.FromMinutes(60));

        var probe = await ProbeAsync(ingress, chained);

        // Refused *after* TLS specifically. A TLS-layer refusal here would mean the certificate was
        // rejected for some reason of its own — wrong chain, wrong extensions, a clock problem —
        // and the test would be passing without ever reaching the admission check it exists to
        // exercise. The status line is asserted on so a future change of refusal code is visible
        // rather than silently absorbed.
        Assert.Equal(Outcome.RefusedAfterTls, probe.Outcome);
        Assert.Equal("HTTP/1.1 403 Forbidden", probe.Status);
    }

    [SkippableFact]
    public async Task Plain_http_on_the_tunnel_port_is_not_proxied()
    {
        // The cheapest thing a scanner tries: skip TLS entirely and speak proxy at the port. Both
        // shapes are covered -- the CONNECT method, and the absolute-form GET that an ordinary
        // forward proxy answers.
        var ingress = Require(StampUnderTest.Ingress, StampUnderTest.IngressVariable);

        Assert.False(await ProbeCleartextTunnelsAsync(
            ingress, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"));
        Assert.False(await ProbeCleartextTunnelsAsync(
            ingress, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"));
    }

    [SkippableTheory]
    [InlineData(22, "SSH — admin access belongs on no public path (D-04: no public SSH)")]
    [InlineData(80, "cleartext HTTP")]
    [InlineData(3128, "the classic forward-proxy port a scanner sweeps for")]
    [InlineData(8080, "the other one")]
    [InlineData(8081, "Envoy's health listener, which exists for the load balancer's probe only")]
    [InlineData(8443, "Envoy's own tunnel listener, which must be reachable only through the LB")]
    [InlineData(9901, "Envoy's admin interface — config dump, stats, and /quitquitquit")]
    public async Task No_port_but_the_tunnel_answers_on_the_ingress_address(int port, string what)
    {
        var ingress = Require(StampUnderTest.Ingress, StampUnderTest.IngressVariable);

        var reachable = await IsReachableAsync(ingress, port);

        Assert.False(reachable, $"Port {port} answered on the ingress address: {what}.");
    }

    private static string Require(string? value, string variable)
    {
        Skip.If(value is null, StampUnderTest.SkipReason(variable));
        return value!;
    }

    /// <summary>
    /// Attempts one CONNECT through TLS and reports only whether a tunnel came out of it.
    /// </summary>
    [SuppressMessage(
        "Security",
        "CA5359:Do not disable certificate validation",
        Justification =
            "This is the scanner, not a client. It arrives at an address it has no relationship "
            + "with, presented with a certificate from an internal CA it has no reason to trust, "
            + "and the question it asks is whether a tunnel opens — not whether the server is who "
            + "it claims. Validating here would turn every probe into a test of this machine's "
            + "trust store. Who issued the node's certificate is asserted directly, in "
            + "The_tunnel_port_answers_and_demands_a_client_certificate.")]
    private static async Task<Probe> ProbeAsync(string ingress, X509Certificate2? clientCertificate)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);

        try
        {
            await socket.ConnectAsync(ingress, StampUnderTest.TunnelPort, timeout.Token);
            await using var network = new NetworkStream(socket, ownsSocket: false);
            await using var tls = new SslStream(network, leaveInnerStreamOpen: true);

            var options = new SslClientAuthenticationOptions
            {
                TargetHost = StampUnderTest.ServerName,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,

                // The node's certificate is issued by the internal CA, which this machine has no
                // reason to trust as a root. Validation is not what is under test here -- whether a
                // tunnel opens is -- and the separate control test asserts who issued it.
                RemoteCertificateValidationCallback = (_, _, _, _) => true,
            };

            if (clientCertificate is not null)
            {
                options.ClientCertificates = [clientCertificate];
            }

            await tls.AuthenticateAsClientAsync(options, timeout.Token);

            var request = Encoding.ASCII.GetBytes(
                "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n");
            await tls.WriteAsync(request, timeout.Token);

            var buffer = new byte[128];
            var read = await tls.ReadAsync(buffer, timeout.Token);
            if (read == 0)
            {
                // Under TLS 1.3 the server finishes its side of the handshake before judging the
                // client, so a refusal at the TLS layer can arrive here as an EOF rather than as an
                // exception above. Still a TLS refusal: no HTTP was ever spoken.
                return new Probe(Outcome.RefusedAtTls, null);
            }

            var status = Encoding.ASCII.GetString(buffer, 0, read).Split('\r')[0];
            Assert.StartsWith("HTTP/1.1", status, StringComparison.Ordinal);

            // Only a 2xx is a tunnel, and only a tunnel is an open proxy. Anything else is the node
            // declining after TLS -- which for a certificate that chains correctly means the
            // sidecar's admission check, and that is a different fact worth telling apart.
            return status.StartsWith("HTTP/1.1 2", StringComparison.Ordinal)
                ? new Probe(Outcome.Tunnelled, status)
                : new Probe(Outcome.RefusedAfterTls, status);
        }
        catch (Exception ex) when (ex is AuthenticationException or IOException or SocketException)
        {
            // The enumerated ways a refused connection dies. A timeout is deliberately not one of
            // them: it propagates and fails the test, because a hang proves nothing either way.
            return new Probe(Outcome.RefusedAtTls, null);
        }
    }

    /// <summary>Speaks proxy at the tunnel port without TLS.</summary>
    private static async Task<bool> ProbeCleartextTunnelsAsync(string ingress, string request)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);

        try
        {
            await socket.ConnectAsync(ingress, StampUnderTest.TunnelPort, timeout.Token);
            await using var network = new NetworkStream(socket, ownsSocket: false);

            await network.WriteAsync(Encoding.ASCII.GetBytes(request), timeout.Token);

            var buffer = new byte[64];
            var read = await network.ReadAsync(buffer, timeout.Token);
            if (read == 0)
            {
                return false;
            }

            var status = Encoding.ASCII.GetString(buffer, 0, read);
            return status.StartsWith("HTTP/1.1 2", StringComparison.Ordinal)
                ? true
                : false;
        }
        catch (Exception ex) when (ex is IOException or SocketException)
        {
            return false;
        }
    }

    /// <summary>Reads the server's certificate and the issuers it will accept from a client.</summary>
    [SuppressMessage(
        "Security",
        "CA5359:Do not disable certificate validation",
        Justification =
            "Reading the presented certificate is the purpose of this method; the callback is how "
            + "SslStream hands it over. Rejecting it would discard the very evidence being "
            + "collected, and the caller asserts on the issuer instead.")]
    private static async Task<(X509Certificate2? Certificate, IReadOnlyList<string> AcceptableIssuers)>
        InspectTlsAsync(string ingress)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
        await socket.ConnectAsync(ingress, StampUnderTest.TunnelPort, timeout.Token);
        await using var network = new NetworkStream(socket, ownsSocket: false);
        await using var tls = new SslStream(network, leaveInnerStreamOpen: true);

        X509Certificate2? presented = null;
        var issuers = new List<string>();

        var options = new SslClientAuthenticationOptions
        {
            TargetHost = StampUnderTest.ServerName,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            RemoteCertificateValidationCallback = (_, certificate, _, _) =>
            {
                if (certificate is not null)
                {
                    presented = X509CertificateLoader.LoadCertificate(certificate.GetRawCertData());
                }

                return true;
            },

            // Invoked because the server asked for a client certificate; the issuer list it asked
            // with is the evidence, so this records it and then declines to present one.
            LocalCertificateSelectionCallback = (_, _, _, _, acceptableIssuers) =>
            {
                issuers.AddRange(acceptableIssuers);
                return null!;
            },
        };

        try
        {
            await tls.AuthenticateAsClientAsync(options, timeout.Token);
        }
        catch (Exception ex) when (ex is AuthenticationException or IOException)
        {
            // Expected: this connection presents no certificate, so it is refused like any other.
            // The callbacks above have already fired by then, which is all this method wanted.
        }

        return (presented, issuers);
    }

    private static async Task<bool> IsReachableAsync(string host, int port)
    {
        // Three seconds against an Azure NSG deny, which drops rather than rejects: a closed port
        // times out and an open one answers immediately, so the wait is only ever paid by ports
        // that pass.
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        using var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);

        try
        {
            await socket.ConnectAsync(host, port, timeout.Token);
            return true;
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException)
        {
            return false;
        }
    }
}
