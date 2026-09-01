using System.Net.Security;
using System.Security.Cryptography;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

namespace Mina.EndpointAgent.Proxy;

/// <summary>Where and how to reach the egress ingress, plus the session client credential.</summary>
/// <param name="Host">Egress ingress host (LB IP/DNS).</param>
/// <param name="Port">Egress ingress port (443 in production).</param>
/// <param name="ServerName">TLS SNI / expected server name presented to the egress.</param>
public sealed record EgressEndpoint(string Host, int Port, string ServerName);

/// <summary>
/// Opens a tunnel by connecting to the egress over mutual TLS and issuing an HTTP/1.1
/// <c>CONNECT</c> for the target (ADR-0001 C-tx). The client certificate is the short-lived,
/// session-bound credential issued by the control plane; the server certificate is validated
/// against Mina's internal CA only (no public trust store), so the agent will not tunnel to an
/// impostor egress.
/// </summary>
/// <remarks>
/// The PoC uses HTTP/1.1 CONNECT (one TLS connection per target) for implementation simplicity.
/// Production moves to HTTP/2 CONNECT so many browser streams share one mTLS connection — a
/// performance change at ~50 concurrent users, not a change to the security properties proven
/// here. Tracked on the ADR-0001 verification register.
/// </remarks>
public sealed class MtlsTunnelConnectionFactory(
    EgressEndpoint endpoint,
    Func<X509Certificate2> clientCertificateProvider,
    X509Certificate2 trustedCaCertificate) : ITunnelConnectionFactory
{
    private readonly EgressEndpoint _endpoint = endpoint ?? throw new ArgumentNullException(nameof(endpoint));

    private readonly Func<X509Certificate2> _clientCertificateProvider =
        clientCertificateProvider ?? throw new ArgumentNullException(nameof(clientCertificateProvider));

    private readonly X509Certificate2 _trustedCaCertificate =
        trustedCaCertificate ?? throw new ArgumentNullException(nameof(trustedCaCertificate));

    /// <summary>id-kp-serverAuth: what an egress listener's certificate must be issued for.</summary>
    private static readonly Oid ServerAuthentication = new("1.3.6.1.5.5.7.3.1");

    public async Task<Stream> ConnectAsync(ConnectTarget target, CancellationToken cancellationToken)
    {
        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        SslStream? tls = null;
        try
        {
            await socket.ConnectAsync(_endpoint.Host, _endpoint.Port, cancellationToken).ConfigureAwait(false);

            tls = new SslStream(new NetworkStream(socket, ownsSocket: true), leaveInnerStreamOpen: false);
            using var clientCert = _clientCertificateProvider();
            var options = new SslClientAuthenticationOptions
            {
                TargetHost = _endpoint.ServerName,
                ClientCertificates = [clientCert],
                RemoteCertificateValidationCallback = ValidateEgressCertificate,
                EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls13
                    | System.Security.Authentication.SslProtocols.Tls12,
            };

            await tls.AuthenticateAsClientAsync(options, cancellationToken).ConfigureAwait(false);

            await tls.WriteAsync(HttpConnect.BuildConnectRequest(target), cancellationToken).ConfigureAwait(false);
            await tls.FlushAsync(cancellationToken).ConfigureAwait(false);

            var status = await HttpConnect.ReadResponseStatusAsync(tls, cancellationToken).ConfigureAwait(false);
            if (status != 200)
            {
                throw new HttpConnectException($"Egress refused CONNECT to {target} with status {status}.");
            }

            return tls;
        }
        catch
        {
            if (tls is not null)
            {
                await tls.DisposeAsync().ConfigureAwait(false);
            }
            else
            {
                socket.Dispose();
            }

            throw;
        }
    }

    /// <summary>
    /// Accepts the egress only if the certificate chains to Mina's CA, is issued *for* the egress
    /// host, and is intended for server authentication.
    /// </summary>
    /// <remarks>
    /// Chaining to the CA is not on its own sufficient, and treating it as sufficient was a real
    /// hole: every endpoint holds a session client certificate issued by this same CA, private key
    /// included. Without the name and purpose checks, anyone able to redirect the agent's
    /// connection could present one of those and terminate the tunnel, reading research traffic in
    /// clear. So the name mismatch reported by <see cref="SslStream"/> is fatal, and the chain is
    /// built with a server-authentication application policy, which a clientAuth-only certificate
    /// cannot satisfy.
    /// </remarks>
    private bool ValidateEgressCertificate(
        object sender,
        X509Certificate? certificate,
        X509Chain? chain,
        SslPolicyErrors sslPolicyErrors)
    {
        if (certificate is null)
        {
            return false;
        }

        // Chain errors are expected — Mina's CA is deliberately not in the machine trust store, and
        // the chain is re-verified against it below. Anything else, and in particular a name
        // mismatch against the expected egress host, is fatal.
        if ((sslPolicyErrors & ~SslPolicyErrors.RemoteCertificateChainErrors) != SslPolicyErrors.None)
        {
            return false;
        }

        using var presented = X509CertificateLoader.LoadCertificate(certificate.GetRawCertData());
        using var verification = new X509Chain();
        verification.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        verification.ChainPolicy.CustomTrustStore.Add(_trustedCaCertificate);
        verification.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        verification.ChainPolicy.ApplicationPolicy.Add(ServerAuthentication);
        return verification.Build(presented);
    }
}
