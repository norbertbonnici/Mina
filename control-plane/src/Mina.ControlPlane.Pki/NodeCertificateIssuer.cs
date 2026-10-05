using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace Mina.ControlPlane.Pki;

/// <summary>
/// Issues server certificates for egress-node Envoy listeners (M2-2d). Every node gets the same
/// configured lifetime — there is no client-chosen TTL the way session certificates have, since a
/// node has no analyst-facing renewal loop yet (rotation is M4-2); <c>mina-fetch-certs.service</c>
/// runs this once at boot.
/// </summary>
public sealed class NodeCertificateIssuer
{
    private readonly CertificateAuthority _authority;
    private readonly TimeSpan _lifetime;

    public NodeCertificateIssuer(CertificateAuthority authority, TimeSpan lifetime)
    {
        ArgumentNullException.ThrowIfNull(authority);
        if (lifetime <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(lifetime), "Node certificate lifetime must be positive.");
        }

        _authority = authority;
        _lifetime = lifetime;
    }

    /// <summary>
    /// Issues a node server certificate by signing a node-generated CSR, so the private key never
    /// leaves the node. <paramref name="dnsNames"/>/<paramref name="ipAddresses"/> are the control
    /// plane's own record of what this region's egress presents as — never taken from the
    /// requester, so a compromised node cannot ask for a certificate naming some other Mina host.
    /// </summary>
    public X509Certificate2 IssueFromCsr(
        byte[] pkcs10Request, IEnumerable<string> dnsNames, IEnumerable<IPAddress> ipAddresses, DateTimeOffset now) =>
        _authority.SignServerCertificateRequest(pkcs10Request, dnsNames, ipAddresses, now, _lifetime);
}
