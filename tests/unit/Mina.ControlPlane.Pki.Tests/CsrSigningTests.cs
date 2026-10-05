using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Mina.ControlPlane.Pki;

namespace Mina.ControlPlane.Pki.Tests;

public class CsrSigningTests
{
    private static readonly DateTimeOffset T0 = new(2026, 8, 31, 9, 0, 0, TimeSpan.Zero);
    private const string ClientAuthOid = "1.3.6.1.5.5.7.3.2";
    private const string ServerAuthOid = "1.3.6.1.5.5.7.3.1";

    private static byte[] CreateCsr(ECDsa key) =>
        new CertificateRequest("CN=mina-agent", key, HashAlgorithmName.SHA256).CreateSigningRequest();

    [Fact]
    public void Signed_certificate_carries_the_requesters_public_key_and_no_private_key()
    {
        using var ca = CertificateAuthority.Create("Mina Test CA", T0, TimeSpan.FromDays(365));
        using var agentKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var csr = CreateCsr(agentKey);

        using var signed = ca.SignClientCertificateRequest(csr, "mina:session:abc", T0, TimeSpan.FromMinutes(60));

        Assert.False(signed.HasPrivateKey); // the key stayed on the endpoint
        using var certKey = signed.GetECDsaPublicKey()!;
        var expected = agentKey.ExportSubjectPublicKeyInfo();
        Assert.Equal(expected, certKey.ExportSubjectPublicKeyInfo());
    }

    [Fact]
    public void Signed_certificate_has_clientauth_eku_session_san_and_chains_to_ca()
    {
        using var ca = CertificateAuthority.Create("Mina Test CA", T0, TimeSpan.FromDays(365));
        using var agentKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using var signed = ca.SignClientCertificateRequest(
            CreateCsr(agentKey), "mina:session:abc", T0, TimeSpan.FromMinutes(60));

        var eku = signed.Extensions.OfType<X509EnhancedKeyUsageExtension>().Single();
        Assert.Contains(eku.EnhancedKeyUsages.Cast<Oid>(), oid => oid.Value == ClientAuthOid);

        var san = signed.Extensions.OfType<X509SubjectAlternativeNameExtension>().Single().Format(false);
        Assert.Contains("mina:session:abc", san, StringComparison.Ordinal);

        using var caPublic = ca.PublicCertificate;
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(caPublic);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationTime = T0.AddMinutes(1).UtcDateTime;
        Assert.True(chain.Build(signed));
    }

    [Fact]
    public void IssueFromCsr_binds_the_session_id_into_the_san()
    {
        var sessionId = Guid.NewGuid();
        using var ca = CertificateAuthority.Create("Mina Test CA", T0, TimeSpan.FromDays(365));
        var issuer = new SessionCertificateIssuer(ca, new SessionCertificatePolicy(TimeSpan.FromMinutes(60)));
        using var agentKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using var signed = issuer.IssueFromCsr(sessionId, CreateCsr(agentKey), T0, TimeSpan.FromMinutes(30));

        var san = signed.Extensions.OfType<X509SubjectAlternativeNameExtension>().Single().Format(false);
        Assert.Contains($"mina:session:{sessionId:D}", san, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void A_tampered_csr_is_rejected()
    {
        using var ca = CertificateAuthority.Create("Mina Test CA", T0, TimeSpan.FromDays(365));
        using var agentKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var csr = CreateCsr(agentKey);
        csr[^1] ^= 0xFF; // corrupt the signature

        Assert.ThrowsAny<CryptographicException>(() =>
            ca.SignClientCertificateRequest(csr, "mina:session:abc", T0, TimeSpan.FromMinutes(60)));
    }

    [Fact]
    public void A_csr_with_a_weak_rsa_key_is_refused_on_both_signing_paths()
    {
        // Verifying the CSR signature proves possession of the key, not that the key is worth
        // certifying. Every Mina requester generates ECDSA P-256; an RSA-1024 request is never
        // legitimate, and a certificate over it would be a tunnel credential cheaper to break than
        // anything the platform chose for itself.
        using var ca = CertificateAuthority.Create("Mina Test CA", T0, TimeSpan.FromDays(365));
        using var weak = RSA.Create(1024);
        var csr = new CertificateRequest("CN=mina-agent", weak, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSigningRequest();

        var client = Assert.ThrowsAny<CryptographicException>(() =>
            ca.SignClientCertificateRequest(csr, "mina:session:abc", T0, TimeSpan.FromMinutes(60)));
        Assert.Contains("1024", client.Message, StringComparison.Ordinal);

        var server = Assert.ThrowsAny<CryptographicException>(() =>
            ca.SignServerCertificateRequest(csr, ["egress.local"], [], T0, TimeSpan.FromDays(30)));
        Assert.Contains("1024", server.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_csr_with_an_acceptable_rsa_key_is_still_signed()
    {
        // The policy is about strength, not about banning RSA outright: a 2048-bit request from a
        // future requester is certified like any other.
        using var ca = CertificateAuthority.Create("Mina Test CA", T0, TimeSpan.FromDays(365));
        using var rsa = RSA.Create(CertificateAuthority.MinimumRsaKeySize);
        var csr = new CertificateRequest("CN=mina-agent", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSigningRequest();

        using var signed = ca.SignClientCertificateRequest(csr, "mina:session:rsa", T0, TimeSpan.FromMinutes(60));

        using var key = signed.GetRSAPublicKey();
        Assert.NotNull(key);
        Assert.Equal(CertificateAuthority.MinimumRsaKeySize, key.KeySize);
    }

    [Theory]
    [InlineData(384)]
    [InlineData(521)]
    public void Larger_nist_curves_are_accepted_alongside_p256(int keySize)
    {
        using var ca = CertificateAuthority.Create("Mina Test CA", T0, TimeSpan.FromDays(365));
        using var key = ECDsa.Create(keySize == 384 ? ECCurve.NamedCurves.nistP384 : ECCurve.NamedCurves.nistP521);

        using var signed = ca.SignClientCertificateRequest(CreateCsr(key), "mina:session:big", T0, TimeSpan.FromMinutes(60));

        using var certKey = signed.GetECDsaPublicKey();
        Assert.Equal(keySize, certKey!.KeySize);
    }

    [Fact]
    public void A_server_csr_is_signed_with_the_requesters_key_and_no_private_key_returned()
    {
        using var ca = CertificateAuthority.Create("Mina Test CA", T0, TimeSpan.FromDays(365));
        using var nodeKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var csr = CreateCsr(nodeKey);

        using var signed = ca.SignServerCertificateRequest(
            csr, ["westeurope.egress.mina.internal"], [], T0, TimeSpan.FromDays(90));

        Assert.False(signed.HasPrivateKey); // the key stayed on the node
        using var certKey = signed.GetECDsaPublicKey()!;
        Assert.Equal(nodeKey.ExportSubjectPublicKeyInfo(), certKey.ExportSubjectPublicKeyInfo());
    }

    [Fact]
    public void A_signed_server_certificate_has_serverauth_eku_the_given_san_and_chains_to_ca()
    {
        using var ca = CertificateAuthority.Create("Mina Test CA", T0, TimeSpan.FromDays(365));
        using var nodeKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using var signed = ca.SignServerCertificateRequest(
            CreateCsr(nodeKey),
            ["westeurope.egress.mina.internal"],
            [IPAddress.Parse("203.0.113.10")],
            T0,
            TimeSpan.FromDays(90));

        var eku = signed.Extensions.OfType<X509EnhancedKeyUsageExtension>().Single();
        Assert.Contains(eku.EnhancedKeyUsages.Cast<Oid>(), oid => oid.Value == ServerAuthOid);

        var san = signed.Extensions.OfType<X509SubjectAlternativeNameExtension>().Single().Format(false);
        Assert.Contains("westeurope.egress.mina.internal", san, StringComparison.Ordinal);
        Assert.Contains("203.0.113.10", san, StringComparison.Ordinal);

        using var caPublic = ca.PublicCertificate;
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(caPublic);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationTime = T0.AddMinutes(1).UtcDateTime;
        Assert.True(chain.Build(signed));
    }

    [Fact]
    public void A_server_csrs_own_requested_extensions_are_ignored()
    {
        // The CSR's own basic-constraints/EKU/SAN mean nothing -- only the CA's own choices reach
        // the issued certificate. A node that asked for a CA certificate, or for a SAN naming some
        // other Mina host, gets neither: this is what stops a compromised node from minting itself
        // (or anything else) a certificate it was not granted.
        using var ca = CertificateAuthority.Create("Mina Test CA", T0, TimeSpan.FromDays(365));
        using var nodeKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=mina-node", nodeKey, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(certificateAuthority: true, false, 0, critical: true));
        var requestedSan = new SubjectAlternativeNameBuilder();
        requestedSan.AddDnsName("mina-cp.example.org");
        request.CertificateExtensions.Add(requestedSan.Build());
        var csr = request.CreateSigningRequest();

        using var signed = ca.SignServerCertificateRequest(
            csr, ["westeurope.egress.mina.internal"], [], T0, TimeSpan.FromDays(90));

        var basicConstraints = signed.Extensions.OfType<X509BasicConstraintsExtension>().Single();
        Assert.False(basicConstraints.CertificateAuthority);
        var san = signed.Extensions.OfType<X509SubjectAlternativeNameExtension>().Single().Format(false);
        Assert.DoesNotContain("mina-cp.example.org", san, StringComparison.Ordinal);
        Assert.Contains("westeurope.egress.mina.internal", san, StringComparison.Ordinal);
    }

    [Fact]
    public void A_tampered_server_csr_is_rejected()
    {
        using var ca = CertificateAuthority.Create("Mina Test CA", T0, TimeSpan.FromDays(365));
        using var nodeKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var csr = CreateCsr(nodeKey);
        csr[^1] ^= 0xFF;

        Assert.ThrowsAny<CryptographicException>(() =>
            ca.SignServerCertificateRequest(csr, ["westeurope.egress.mina.internal"], [], T0, TimeSpan.FromDays(90)));
    }

    [Fact]
    public void NodeCertificateIssuer_applies_its_configured_lifetime_regardless_of_caller()
    {
        // Unlike SessionCertificateIssuer there is no caller-chosen TTL to validate against a max
        // -- every node gets the same configured lifetime, so the issuer itself is what fixes it.
        using var ca = CertificateAuthority.Create("Mina Test CA", T0, TimeSpan.FromDays(3650));
        var issuer = new NodeCertificateIssuer(ca, TimeSpan.FromDays(90));
        using var nodeKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using var signed = issuer.IssueFromCsr(CreateCsr(nodeKey), ["westeurope.egress.mina.internal"], [], T0);

        Assert.Equal(T0.AddDays(90).UtcDateTime, signed.NotAfter.ToUniversalTime(), TimeSpan.FromSeconds(1));
    }

    [Fact]
    public void NodeCertificateIssuer_refuses_a_non_positive_lifetime_at_construction()
    {
        using var ca = CertificateAuthority.Create("Mina Test CA", T0, TimeSpan.FromDays(365));

        Assert.Throws<ArgumentOutOfRangeException>(() => new NodeCertificateIssuer(ca, TimeSpan.Zero));
    }
}
