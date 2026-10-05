using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Mina.EndpointAgent.Session;

/// <summary>
/// The key pair backing one session certificate. The private key is generated here on the endpoint
/// and never leaves it: the control plane only ever sees a CSR and returns a signed public
/// certificate. A fresh instance is created for every issuance and every renewal, so a session
/// credential is never reused across leases.
/// </summary>
public sealed class SessionKeyMaterial : IDisposable
{
    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    /// <summary>Produces the PKCS#10 request the control plane signs.</summary>
    public byte[] CreateCertificateSigningRequest() =>
        new CertificateRequest("CN=mina-agent", _key, HashAlgorithmName.SHA256).CreateSigningRequest();

    /// <summary>
    /// Combines the issued certificate with the locally held private key and returns it as PKCS#12
    /// bytes, from which fresh <see cref="X509Certificate2"/> instances can be loaded per TLS
    /// handshake. Going through PKCS#12 also gives a key handle <c>SslStream</c> accepts on every
    /// platform, which a directly attached ephemeral key is not guaranteed to be.
    /// </summary>
    public byte[] ToClientCertificatePkcs12(string issuedCertificatePem)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(issuedCertificatePem);

        using var issued = X509Certificate2.CreateFromPem(issuedCertificatePem);
        using var withKey = issued.CopyWithPrivateKey(_key);
        return withKey.Export(X509ContentType.Pkcs12);
    }

    public void Dispose() => _key.Dispose();
}
