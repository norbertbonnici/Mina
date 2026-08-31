using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Mina.ControlPlane.Pki;

namespace Mina.ControlPlane.Pki.Tests;

public class CsrSigningTests
{
    private static readonly DateTimeOffset T0 = new(2026, 8, 31, 9, 0, 0, TimeSpan.Zero);
    private const string ClientAuthOid = "1.3.6.1.5.5.7.3.2";

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
}
