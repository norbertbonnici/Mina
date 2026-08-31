using System.Net.Security;
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

        using var presented = X509CertificateLoader.LoadCertificate(certificate.GetRawCertData());
        using var verification = new X509Chain();
        verification.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        verification.ChainPolicy.CustomTrustStore.Add(_trustedCaCertificate);
        verification.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        return verification.Build(presented);
    }
}
