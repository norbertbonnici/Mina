using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Mina.ControlPlane.Pki;

/// <summary>
/// Mina's internal certificate authority. In production the CA private key lives in Key Vault
/// and never leaves it (ARCHITECTURE §3.2): <see cref="CreateFromRemoteSigner"/> is that CA, and
/// <see cref="Create"/> is the local-key CA used by tests and development.
/// </summary>
/// <remarks>
/// <para>
/// The issuance logic below is shared by both: the only difference between a CA whose key is in
/// this process and one whose key is in a vault is which <see cref="X509SignatureGenerator"/>
/// produces the signature at the end. That is deliberate — it means every test of what a Mina
/// certificate contains is also a test of what the Key Vault CA issues, and the part that is
/// genuinely untestable without Azure is narrowed to "does the vault return a signature".
/// </para>
/// <para>
/// The CA issues two leaf kinds: server certificates for egress Envoy listeners (serverAuth)
/// and short-lived client certificates bound to a research session (clientAuth), which the
/// egress uses to authenticate and attribute each tunnel (ADR-0001 C-tx). Elliptic-curve keys
/// keep issuance cheap at session-renewal rates.
/// </para>
/// </remarks>
public sealed class CertificateAuthority : IDisposable
{
    /// <summary>
    /// Digest used to sign leaf certificates with a local key. Retained as SHA-256 because it is
    /// what this CA has always issued with; a remote signer uses its own key's digest instead,
    /// since an EC key of a given curve has exactly one matching ECDSA digest size.
    /// </summary>
    private static readonly HashAlgorithmName LocalLeafDigest = HashAlgorithmName.SHA256;

    private readonly X509Certificate2 _signingCertificate;
    private readonly X509SignatureGenerator _generator;
    private readonly HashAlgorithmName _signatureDigest;
    private readonly IDisposable? _generatorLifetime;

    private CertificateAuthority(
        X509Certificate2 signingCertificate,
        X509SignatureGenerator generator,
        HashAlgorithmName signatureDigest,
        IDisposable? generatorLifetime)
    {
        _signingCertificate = signingCertificate;
        _generator = generator;
        _signatureDigest = signatureDigest;
        _generatorLifetime = generatorLifetime;
    }

    /// <summary>The CA certificate without its private key — safe to distribute as a trust root.</summary>
    public X509Certificate2 PublicCertificate =>
        X509CertificateLoader.LoadCertificate(_signingCertificate.RawData);

    /// <summary>
    /// A CA with a local key pair, generated here. Development and tests only: the key is in
    /// process memory and, for the ephemeral development provider, is discarded on restart.
    /// </summary>
    public static CertificateAuthority Create(
        string commonName,
        DateTimeOffset notBefore,
        TimeSpan lifetime)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(commonName);
        RequirePositive(lifetime, "CA lifetime must be positive.");

        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var request = WithCaExtensions(new CertificateRequest(
            new X500DistinguishedName($"CN={commonName}"), key, HashAlgorithmName.SHA384));

        // Portable takes ownership of the certificate it is handed and disposes it.
        var caCertificate = request.CreateSelfSigned(notBefore, notBefore + lifetime);
        return FromLocalKey(Portable(caCertificate));
    }

    /// <summary>
    /// The production CA (M2-2c): an existing CA certificate plus a signer that holds the private
    /// key elsewhere and will not give it up. Takes ownership of <paramref name="caCertificate"/>,
    /// which is disposed with the returned authority.
    /// </summary>
    /// <remarks>
    /// The certificate is checked against the signer before anything is issued. A CA certificate
    /// and a signing key that do not belong together produce certificates that verify against
    /// neither — and would do so silently, at the moment an analyst first tried to browse, on
    /// every node at once. Catching it at startup makes it a deployment error instead.
    /// </remarks>
    public static CertificateAuthority CreateFromRemoteSigner(
        X509Certificate2 caCertificate, IRemoteCaSigner signer)
    {
        ArgumentNullException.ThrowIfNull(caCertificate);
        ArgumentNullException.ThrowIfNull(signer);

        var basicConstraints = caCertificate.Extensions
            .OfType<X509BasicConstraintsExtension>()
            .FirstOrDefault();
        if (basicConstraints is not { CertificateAuthority: true })
        {
            throw new ArgumentException(
                $"'{caCertificate.Subject}' is not a CA certificate (basic constraints do not assert cA).",
                nameof(caCertificate));
        }

        var keyUsage = caCertificate.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
        if (keyUsage is not null && !keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.KeyCertSign))
        {
            throw new ArgumentException(
                $"'{caCertificate.Subject}' does not carry the keyCertSign key usage.", nameof(caCertificate));
        }

        var certificateKey = caCertificate.PublicKey.ExportSubjectPublicKeyInfo();
        if (!CryptographicOperations.FixedTimeEquals(certificateKey, signer.SubjectPublicKeyInfo.Span))
        {
            throw new ArgumentException(
                $"CA certificate '{caCertificate.Subject}' does not match signing key {signer.KeyDescription}: "
                + "the certificate's public key is a different key. Certificates issued this way would "
                + "chain to nothing.",
                nameof(caCertificate));
        }

        var generator = new RemoteCaSignatureGenerator(signer);
        return new CertificateAuthority(caCertificate, generator, signer.HashAlgorithm, generator);
    }

    /// <summary>
    /// Self-signs a CA certificate using a key held elsewhere — the one-time bootstrap that gives a
    /// Key Vault signing key a certificate to be a CA with (M2-2c). Returns the public certificate;
    /// there is no private key to return, which is the point.
    /// </summary>
    public static X509Certificate2 SelfSignFromRemoteSigner(
        string commonName,
        IRemoteCaSigner signer,
        DateTimeOffset notBefore,
        TimeSpan lifetime)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(commonName);
        ArgumentNullException.ThrowIfNull(signer);
        RequirePositive(lifetime, "CA lifetime must be positive.");

        using var generator = new RemoteCaSignatureGenerator(signer);
        var request = WithCaExtensions(new CertificateRequest(
            new X500DistinguishedName($"CN={commonName}"), generator.PublicKey, signer.HashAlgorithm));

        // A self-signed certificate is one whose issuer name is its own subject; the vault signs it
        // with the same key the certificate attests to.
        var serial = RandomNumberGenerator.GetBytes(16);
        return request.Create(
            request.SubjectName, generator, notBefore, notBefore + lifetime, serial);
    }

    /// <summary>Issues a server certificate for an egress node listener.</summary>
    public X509Certificate2 IssueServerCertificate(
        string commonName,
        IEnumerable<string> dnsNames,
        IEnumerable<IPAddress> ipAddresses,
        DateTimeOffset notBefore,
        TimeSpan lifetime)
    {
        ArgumentNullException.ThrowIfNull(dnsNames);
        ArgumentNullException.ThrowIfNull(ipAddresses);

        var san = new SubjectAlternativeNameBuilder();
        var any = false;
        foreach (var dns in dnsNames)
        {
            san.AddDnsName(dns);
            any = true;
        }

        foreach (var ip in ipAddresses)
        {
            san.AddIpAddress(ip);
            any = true;
        }

        return IssueLeaf(
            commonName,
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
            OidClientOrServer.ServerAuth,
            any ? san : null,
            notBefore,
            lifetime);
    }

    /// <summary>
    /// Issues a client certificate, generating the key pair server-side. Prefer
    /// <see cref="SignClientCertificateRequest"/> for production issuance so the private key never
    /// leaves the endpoint; this overload is a convenience for tests and local tooling.
    /// <paramref name="sessionUri"/>, when supplied, is embedded as a SAN URI so the egress can
    /// attribute the tunnel to a session without a lookup.
    /// </summary>
    public X509Certificate2 IssueClientCertificate(
        string commonName,
        string? sessionUri,
        DateTimeOffset notBefore,
        TimeSpan lifetime)
    {
        return IssueLeaf(
            commonName,
            X509KeyUsageFlags.DigitalSignature,
            OidClientOrServer.ClientAuth,
            BuildSessionSan(sessionUri),
            notBefore,
            lifetime);
    }

    /// <summary>
    /// Signs a PKCS#10 certificate signing request generated on the endpoint, returning a client
    /// certificate (public only — the private key stays with the requester). The CSR signature is
    /// verified, proving the requester holds the corresponding private key; the CSR's own
    /// requested extensions are ignored and the CA sets clientAuth EKU, key usage and the session
    /// SAN itself.
    /// </summary>
    public X509Certificate2 SignClientCertificateRequest(
        byte[] pkcs10Request,
        string? sessionUri,
        DateTimeOffset notBefore,
        TimeSpan lifetime)
    {
        ArgumentNullException.ThrowIfNull(pkcs10Request);
        RequirePositive(lifetime, "Certificate lifetime must be positive.");

        // Verifies the CSR self-signature; throws if the requester does not hold the private key.
        // The digest passed here is the one the issued certificate is signed with, not the one the
        // CSR was signed with — so it follows this CA's key, not the requester's choice.
        var request = CertificateRequest.LoadSigningRequest(
            pkcs10Request,
            _signatureDigest,
            CertificateRequestLoadOptions.Default);

        request.CertificateExtensions.Clear();
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension([OidClientOrServer.ClientAuth], critical: false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));
        var san = BuildSessionSan(sessionUri);
        if (san is not null)
        {
            request.CertificateExtensions.Add(san.Build());
        }

        var effectiveNotBefore = notBefore < _signingCertificate.NotBefore.ToUniversalTime()
            ? _signingCertificate.NotBefore.ToUniversalTime()
            : notBefore;
        var serial = RandomNumberGenerator.GetBytes(16);

        // No CopyWithPrivateKey: the returned certificate carries only the public key.
        return request.Create(
            _signingCertificate.SubjectName, _generator, effectiveNotBefore, ClampNotAfter(notBefore + lifetime), serial);
    }

    /// <summary>
    /// Signs a PKCS#10 certificate signing request generated on an egress node, returning a server
    /// certificate (public only — the private key stays with the node, the same guarantee
    /// <see cref="SignClientCertificateRequest"/> gives session certificates). The CSR signature is
    /// verified, proving the node holds the corresponding private key; the CSR's own requested
    /// extensions are ignored and the CA sets serverAuth EKU, key usage and the SAN itself. The SAN
    /// is never taken from the requester — it is exactly the discipline
    /// <see cref="SignClientCertificateRequest"/> applies to the session SAN, and matters more here:
    /// a server certificate for a name of the requester's choosing is what a compromised node could
    /// use to impersonate any other Mina host under this CA, not just itself.
    /// </summary>
    public X509Certificate2 SignServerCertificateRequest(
        byte[] pkcs10Request,
        IEnumerable<string> dnsNames,
        IEnumerable<IPAddress> ipAddresses,
        DateTimeOffset notBefore,
        TimeSpan lifetime)
    {
        ArgumentNullException.ThrowIfNull(pkcs10Request);
        ArgumentNullException.ThrowIfNull(dnsNames);
        ArgumentNullException.ThrowIfNull(ipAddresses);
        RequirePositive(lifetime, "Certificate lifetime must be positive.");

        // Verifies the CSR self-signature; throws if the requester does not hold the private key.
        var request = CertificateRequest.LoadSigningRequest(
            pkcs10Request,
            _signatureDigest,
            CertificateRequestLoadOptions.Default);

        request.CertificateExtensions.Clear();
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, critical: true));
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension([OidClientOrServer.ServerAuth], critical: false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

        var san = new SubjectAlternativeNameBuilder();
        var any = false;
        foreach (var dns in dnsNames)
        {
            san.AddDnsName(dns);
            any = true;
        }

        foreach (var ip in ipAddresses)
        {
            san.AddIpAddress(ip);
            any = true;
        }

        if (any)
        {
            request.CertificateExtensions.Add(san.Build());
        }

        var effectiveNotBefore = notBefore < _signingCertificate.NotBefore.ToUniversalTime()
            ? _signingCertificate.NotBefore.ToUniversalTime()
            : notBefore;
        var serial = RandomNumberGenerator.GetBytes(16);

        // No CopyWithPrivateKey: the returned certificate carries only the public key.
        return request.Create(
            _signingCertificate.SubjectName, _generator, effectiveNotBefore, ClampNotAfter(notBefore + lifetime), serial);
    }

    /// <summary>
    /// The extensions that make a certificate this platform's CA, applied identically whether the
    /// key signing it is local or in a vault.
    /// </summary>
    private static CertificateRequest WithCaExtensions(CertificateRequest request)
    {
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(
            certificateAuthority: true, hasPathLengthConstraint: true, pathLengthConstraint: 0, critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, critical: true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));
        return request;
    }

    private static CertificateAuthority FromLocalKey(X509Certificate2 signingCertificate)
    {
        // The generator holds the private key, so its lifetime is the CA's: disposed together.
        var key = signingCertificate.GetECDsaPrivateKey()
            ?? throw new ArgumentException(
                "A locally-keyed CA certificate must carry its ECDSA private key.", nameof(signingCertificate));
        return new CertificateAuthority(
            signingCertificate, X509SignatureGenerator.CreateForECDsa(key), LocalLeafDigest, key);
    }

    private static SubjectAlternativeNameBuilder? BuildSessionSan(string? sessionUri)
    {
        if (string.IsNullOrWhiteSpace(sessionUri))
        {
            return null;
        }

        var san = new SubjectAlternativeNameBuilder();
        san.AddUri(new Uri(sessionUri, UriKind.Absolute));
        return san;
    }

    private X509Certificate2 IssueLeaf(
        string commonName,
        X509KeyUsageFlags keyUsage,
        Oid extendedKeyUsage,
        SubjectAlternativeNameBuilder? san,
        DateTimeOffset notBefore,
        TimeSpan lifetime)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(commonName);
        RequirePositive(lifetime, "Certificate lifetime must be positive.");

        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={commonName}", key, _signatureDigest);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(keyUsage, critical: true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([extendedKeyUsage], critical: false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));
        if (san is not null)
        {
            request.CertificateExtensions.Add(san.Build());
        }

        // Leaf validity is clamped to the CA's own window so a leaf can never outlive its issuer.
        var notAfter = ClampNotAfter(notBefore + lifetime);
        if (notBefore < _signingCertificate.NotBefore.ToUniversalTime())
        {
            notBefore = _signingCertificate.NotBefore.ToUniversalTime();
        }

        var serial = RandomNumberGenerator.GetBytes(16);
        using var issued = request.Create(
            _signingCertificate.SubjectName, _generator, notBefore, notAfter, serial);
        using var withKey = issued.CopyWithPrivateKey(key);
        return Portable(withKey);
    }

    private DateTimeOffset ClampNotAfter(DateTimeOffset requested)
    {
        var caNotAfter = _signingCertificate.NotAfter.ToUniversalTime();
        return requested > caNotAfter ? caNotAfter : requested;
    }

    private static void RequirePositive(TimeSpan lifetime, string message)
    {
        if (lifetime <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(lifetime), message);
        }
    }

    /// <summary>
    /// Round-trips a certificate through PKCS#12 so its private key is usable by
    /// <c>SslStream</c> across platforms (macOS in particular rejects some ephemeral keys).
    /// </summary>
    private static X509Certificate2 Portable(X509Certificate2 certificate)
    {
        try
        {
            var pfx = certificate.Export(X509ContentType.Pkcs12);
            return X509CertificateLoader.LoadPkcs12(pfx, password: null, X509KeyStorageFlags.Exportable);
        }
        finally
        {
            certificate.Dispose();
        }
    }

    public void Dispose()
    {
        _generatorLifetime?.Dispose();
        _signingCertificate.Dispose();
    }

    private static class OidClientOrServer
    {
        public static Oid ServerAuth { get; } = new("1.3.6.1.5.5.7.3.1");

        public static Oid ClientAuth { get; } = new("1.3.6.1.5.5.7.3.2");
    }
}
