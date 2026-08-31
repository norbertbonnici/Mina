using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Mina.ControlPlane.Pki;

/// <summary>
/// Mina's internal certificate authority. In production the CA private key lives in Key Vault
/// and never leaves it (ARCHITECTURE §3.2); this type is the issuance logic exercised by tests
/// and the M1 PoC, and is the seam a Key-Vault-backed signer implements later.
/// </summary>
/// <remarks>
/// The CA issues two leaf kinds: server certificates for egress Envoy listeners (serverAuth)
/// and short-lived client certificates bound to a research session (clientAuth), which the
/// egress uses to authenticate and attribute each tunnel (ADR-0001 C-tx). Elliptic-curve keys
/// keep issuance cheap at session-renewal rates.
/// </remarks>
public sealed class CertificateAuthority : IDisposable
{
    private readonly X509Certificate2 _signingCertificate;

    private CertificateAuthority(X509Certificate2 signingCertificate)
    {
        _signingCertificate = signingCertificate;
    }

    /// <summary>The CA certificate without its private key — safe to distribute as a trust root.</summary>
    public X509Certificate2 PublicCertificate =>
        X509CertificateLoader.LoadCertificate(_signingCertificate.RawData);

    public static CertificateAuthority Create(
        string commonName,
        DateTimeOffset notBefore,
        TimeSpan lifetime)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(commonName);
        if (lifetime <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(lifetime), "CA lifetime must be positive.");
        }

        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var request = new CertificateRequest($"CN={commonName}", key, HashAlgorithmName.SHA384);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(
            certificateAuthority: true, hasPathLengthConstraint: true, pathLengthConstraint: 0, critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, critical: true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

        var caCertificate = request.CreateSelfSigned(notBefore, notBefore + lifetime);
        return new CertificateAuthority(Portable(caCertificate));
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
        if (lifetime <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(lifetime), "Certificate lifetime must be positive.");
        }

        // Verifies the CSR self-signature; throws if the requester does not hold the private key.
        var request = CertificateRequest.LoadSigningRequest(
            pkcs10Request,
            HashAlgorithmName.SHA256,
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
        return request.Create(_signingCertificate, effectiveNotBefore, ClampNotAfter(notBefore + lifetime), serial);
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
        if (lifetime <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(lifetime), "Certificate lifetime must be positive.");
        }

        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={commonName}", key, HashAlgorithmName.SHA256);
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
        using var issued = request.Create(_signingCertificate, notBefore, notAfter, serial);
        using var withKey = issued.CopyWithPrivateKey(key);
        return Portable(withKey);
    }

    private DateTimeOffset ClampNotAfter(DateTimeOffset requested)
    {
        var caNotAfter = _signingCertificate.NotAfter.ToUniversalTime();
        return requested > caNotAfter ? caNotAfter : requested;
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

    public void Dispose() => _signingCertificate.Dispose();

    private static class OidClientOrServer
    {
        public static Oid ServerAuth { get; } = new("1.3.6.1.5.5.7.3.1");

        public static Oid ClientAuth { get; } = new("1.3.6.1.5.5.7.3.2");
    }
}
