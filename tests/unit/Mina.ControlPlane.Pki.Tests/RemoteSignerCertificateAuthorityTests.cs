using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Mina.ControlPlane.Pki;

namespace Mina.ControlPlane.Pki.Tests;

/// <summary>
/// The production CA (M2-2c): the signing key is in Key Vault and this process cannot read it.
/// These tests stand a local key in the vault's place — one that answers exactly as Key Vault does,
/// a raw r‖s signature over a digest and nothing else — so everything between "the control plane
/// decides to issue a certificate" and "the vault returns bytes" is exercised without Azure. What
/// is deliberately not covered here is the Azure SDK call itself; that is verified against the real
/// vault by `mina-ca bootstrap --dry-run` (see BACKLOG M2-2c for the evidence).
/// </summary>
public class RemoteSignerCertificateAuthorityTests
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 4, 9, 0, 0, TimeSpan.Zero);

    [Fact]
    public void A_session_certificate_signed_by_the_remote_key_chains_to_the_ca()
    {
        using var vault = new FakeVaultKey();
        using var caCertificate = CertificateAuthority.SelfSignFromRemoteSigner(
            "Mina Internal CA", vault, T0, TimeSpan.FromDays(365));
        using var ca = CertificateAuthority.CreateFromRemoteSigner(caCertificate, vault);

        using var leaf = ca.IssueClientCertificate(
            "mina-session-1", "mina:session:1", T0, TimeSpan.FromMinutes(60));

        Assert.True(ChainBuilds(ca, leaf));
    }

    [Fact]
    public void The_ca_certificate_it_signs_for_itself_is_a_usable_root()
    {
        using var vault = new FakeVaultKey();
        using var caCertificate = CertificateAuthority.SelfSignFromRemoteSigner(
            "Mina Internal CA", vault, T0, TimeSpan.FromDays(365));

        // Self-signed: the vault key both signs it and is the key it attests to. Its own signature
        // must therefore verify against its own public key, or it is not a root of anything.
        Assert.False(caCertificate.HasPrivateKey);
        Assert.True(caCertificate.Extensions.OfType<X509BasicConstraintsExtension>().Single().CertificateAuthority);
        Assert.True(caCertificate.Extensions.OfType<X509KeyUsageExtension>().Single()
            .KeyUsages.HasFlag(X509KeyUsageFlags.KeyCertSign));
        Assert.True(SignatureVerifies(caCertificate, caCertificate));
    }

    [Fact]
    public void The_signature_is_der_encoded_the_way_x509_requires()
    {
        // Key Vault returns the raw fixed-width r‖s pair; X.509 wants a DER SEQUENCE of two
        // integers. Getting this wrong produces a certificate carrying the right numbers in an
        // encoding nothing accepts — so the conversion is load-bearing, and this reads the bytes
        // back rather than trusting that a chain built once.
        using var vault = new FakeVaultKey();
        using var caCertificate = CertificateAuthority.SelfSignFromRemoteSigner(
            "Mina Internal CA", vault, T0, TimeSpan.FromDays(365));
        using var ca = CertificateAuthority.CreateFromRemoteSigner(caCertificate, vault);
        using var leaf = ca.IssueClientCertificate("mina-session-2", null, T0, TimeSpan.FromMinutes(60));

        var signature = SignatureOf(leaf);
        var reader = new AsnReader(signature, AsnEncodingRules.DER).ReadSequence();
        var r = reader.ReadIntegerBytes();
        var s = reader.ReadIntegerBytes();

        reader.ThrowIfNotEmpty();
        Assert.False(r.IsEmpty);
        Assert.False(s.IsEmpty);
        Assert.True(SignatureVerifies(leaf, caCertificate));
    }

    [Fact]
    public void Only_a_digest_ever_reaches_the_vault()
    {
        // SR-005 is about the key never leaving the vault; this is the other half of the same
        // boundary — what crosses it going the other way. The vault sees a 32-byte SHA-256 digest,
        // never the certificate it is signing.
        using var vault = new FakeVaultKey();
        using var caCertificate = CertificateAuthority.SelfSignFromRemoteSigner(
            "Mina Internal CA", vault, T0, TimeSpan.FromDays(365));
        using var ca = CertificateAuthority.CreateFromRemoteSigner(caCertificate, vault);
        using var leaf = ca.IssueClientCertificate("mina-session-3", "mina:session:3", T0, TimeSpan.FromMinutes(60));

        Assert.NotEmpty(vault.SignedDigests);
        Assert.All(vault.SignedDigests, digest => Assert.Equal(32, digest.Length));
    }

    [Fact]
    public void A_ca_certificate_that_does_not_match_the_signing_key_is_refused()
    {
        // The failure this prevents is silent and total: certificates would be signed by one key
        // and presented as issued by a certificate holding another, so every session certificate
        // on every node would fail validation at once, at the moment an analyst first browsed.
        using var vault = new FakeVaultKey();
        using var otherVault = new FakeVaultKey();
        using var strangerCertificate = CertificateAuthority.SelfSignFromRemoteSigner(
            "Some Other CA", otherVault, T0, TimeSpan.FromDays(365));

        var failure = Assert.Throws<ArgumentException>(
            () => CertificateAuthority.CreateFromRemoteSigner(strangerCertificate, vault));

        Assert.Contains("does not match signing key", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_certificate_that_is_not_a_ca_is_refused()
    {
        using var vault = new FakeVaultKey();
        using var caCertificate = CertificateAuthority.SelfSignFromRemoteSigner(
            "Mina Internal CA", vault, T0, TimeSpan.FromDays(365));
        using var ca = CertificateAuthority.CreateFromRemoteSigner(caCertificate, vault);

        // A leaf this CA issued: correctly signed, wrong shape entirely.
        using var leaf = ca.IssueClientCertificate("mina-session-4", null, T0, TimeSpan.FromMinutes(60));
        using var leafPublicOnly = X509CertificateLoader.LoadCertificate(leaf.RawData);

        var failure = Assert.Throws<ArgumentException>(
            () => CertificateAuthority.CreateFromRemoteSigner(leafPublicOnly, vault));

        Assert.Contains("not a CA certificate", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void An_endpoint_csr_is_signed_by_the_remote_key_and_the_key_stays_with_the_endpoint()
    {
        using var vault = new FakeVaultKey();
        using var caCertificate = CertificateAuthority.SelfSignFromRemoteSigner(
            "Mina Internal CA", vault, T0, TimeSpan.FromDays(365));
        using var ca = CertificateAuthority.CreateFromRemoteSigner(caCertificate, vault);

        using var endpointKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var csr = new CertificateRequest("CN=mina-endpoint", endpointKey, HashAlgorithmName.SHA256)
            .CreateSigningRequest();

        using var issued = ca.SignClientCertificateRequest(
            csr, "mina:session:5", T0, TimeSpan.FromMinutes(60));

        Assert.False(issued.HasPrivateKey);
        Assert.True(ChainBuilds(ca, issued));
    }

    [Fact]
    public void A_leaf_cannot_outlive_the_remote_ca()
    {
        using var vault = new FakeVaultKey();
        using var caCertificate = CertificateAuthority.SelfSignFromRemoteSigner(
            "Short Remote CA", vault, T0, TimeSpan.FromDays(2));
        using var ca = CertificateAuthority.CreateFromRemoteSigner(caCertificate, vault);

        using var leaf = ca.IssueClientCertificate("mina-session-6", null, T0, TimeSpan.FromDays(30));

        Assert.True(leaf.NotAfter.ToUniversalTime() <= caCertificate.NotAfter.ToUniversalTime().AddSeconds(1));
    }

    [Fact]
    public void A_signature_of_the_wrong_shape_is_rejected_rather_than_encoded_into_a_certificate()
    {
        // Guards the boundary itself: an HSM or vault that answered with something other than the
        // fixed-width r‖s pair must not have that reinterpreted as a valid signature.
        using var vault = new FakeVaultKey();
        using var caCertificate = CertificateAuthority.SelfSignFromRemoteSigner(
            "Mina Internal CA", vault, T0, TimeSpan.FromDays(365));
        using var truncating = new TruncatingVaultKey(vault);
        using var ca = CertificateAuthority.CreateFromRemoteSigner(caCertificate, truncating);

        Assert.Throws<CryptographicException>(
            () => ca.IssueClientCertificate("mina-session-7", null, T0, TimeSpan.FromMinutes(60)));
    }

    private static bool ChainBuilds(CertificateAuthority ca, X509Certificate2 leaf)
    {
        using var caCert = ca.PublicCertificate;
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(caCert);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationTime = T0.AddMinutes(1).UtcDateTime;
        return chain.Build(leaf);
    }

    /// <summary>Verifies <paramref name="certificate"/>'s signature against the issuer's public key.</summary>
    private static bool SignatureVerifies(X509Certificate2 certificate, X509Certificate2 issuer)
    {
        using var issuerKey = issuer.GetECDsaPublicKey()!;
        return issuerKey.VerifyData(
            TbsBytes(certificate),
            SignatureOf(certificate),
            HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence);
    }

    /// <summary>The to-be-signed portion of a certificate: the first element of the outer SEQUENCE.</summary>
    private static byte[] TbsBytes(X509Certificate2 certificate)
    {
        var outer = new AsnReader(certificate.RawData, AsnEncodingRules.DER).ReadSequence();
        return outer.ReadEncodedValue().ToArray();
    }

    /// <summary>The signature BIT STRING: the third element of the outer SEQUENCE.</summary>
    private static byte[] SignatureOf(X509Certificate2 certificate)
    {
        var outer = new AsnReader(certificate.RawData, AsnEncodingRules.DER).ReadSequence();
        outer.ReadEncodedValue();
        outer.ReadEncodedValue();
        return outer.ReadBitString(out _);
    }

    /// <summary>
    /// A stand-in for the Key Vault key: it signs a digest and returns the raw fixed-width r‖s pair,
    /// which is what Key Vault's ES256 returns and is not what X.509 expects — so a test using this
    /// exercises the same conversion the real vault does.
    /// </summary>
    private sealed class FakeVaultKey : IRemoteCaSigner, IDisposable
    {
        private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly List<byte[]> _signedDigests = [];

        public ReadOnlyMemory<byte> SubjectPublicKeyInfo => _key.ExportSubjectPublicKeyInfo();

        public HashAlgorithmName HashAlgorithm => HashAlgorithmName.SHA256;

        public string KeyDescription => "fake-vault/keys/mina-internal-ca";

        public IReadOnlyList<byte[]> SignedDigests => _signedDigests;

        public byte[] SignHash(ReadOnlySpan<byte> digest, HashAlgorithmName hashAlgorithm)
        {
            _signedDigests.Add(digest.ToArray());
            return _key.SignHash(digest.ToArray(), DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }

        public void Dispose() => _key.Dispose();
    }

    /// <summary>A vault that returns a malformed signature.</summary>
    private sealed class TruncatingVaultKey(IRemoteCaSigner inner) : IRemoteCaSigner, IDisposable
    {
        public ReadOnlyMemory<byte> SubjectPublicKeyInfo => inner.SubjectPublicKeyInfo;

        public HashAlgorithmName HashAlgorithm => inner.HashAlgorithm;

        public string KeyDescription => inner.KeyDescription;

        public byte[] SignHash(ReadOnlySpan<byte> digest, HashAlgorithmName hashAlgorithm) =>
            inner.SignHash(digest, hashAlgorithm)[..^1];

        public void Dispose()
        {
        }
    }
}
