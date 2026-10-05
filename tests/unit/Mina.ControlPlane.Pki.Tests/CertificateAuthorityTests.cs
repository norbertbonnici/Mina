using System.Net;
using System.Security.Cryptography.X509Certificates;
using Mina.ControlPlane.Pki;

namespace Mina.ControlPlane.Pki.Tests;

public class CertificateAuthorityTests
{
    private static readonly DateTimeOffset T0 = new(2026, 8, 31, 9, 0, 0, TimeSpan.Zero);

    private const string ServerAuthOid = "1.3.6.1.5.5.7.3.1";
    private const string ClientAuthOid = "1.3.6.1.5.5.7.3.2";

    private static CertificateAuthority NewCa() =>
        CertificateAuthority.Create("Mina Test CA", T0, TimeSpan.FromDays(365));

    [Fact]
    public void Ca_is_a_v3_certificate_authority()
    {
        using var ca = NewCa();
        using var caCert = ca.PublicCertificate;

        var basicConstraints = caCert.Extensions.OfType<X509BasicConstraintsExtension>().Single();
        Assert.True(basicConstraints.CertificateAuthority);
        Assert.Equal(3, caCert.Version);
    }

    [Fact]
    public void PublicCertificate_does_not_expose_the_private_key()
    {
        using var ca = NewCa();
        using var caCert = ca.PublicCertificate;

        Assert.False(caCert.HasPrivateKey);
    }

    [Fact]
    public void Server_certificate_has_serverauth_eku_and_chains_to_ca()
    {
        using var ca = NewCa();
        using var server = ca.IssueServerCertificate(
            "egress.mina.example",
            ["egress.mina.example"],
            [IPAddress.Parse("20.0.0.5")],
            T0,
            TimeSpan.FromDays(30));

        Assert.True(server.HasPrivateKey);
        AssertEku(server, ServerAuthOid);
        AssertChainsTo(ca, server);

        var san = server.Extensions.OfType<X509SubjectAlternativeNameExtension>().Single().Format(false);
        Assert.Contains("egress.mina.example", san, StringComparison.Ordinal);
        Assert.Contains("20.0.0.5", san, StringComparison.Ordinal);
    }

    [Fact]
    public void Client_certificate_has_clientauth_eku_and_chains_to_ca()
    {
        using var ca = NewCa();
        using var client = ca.IssueClientCertificate("mina-agent", "mina:session:demo", T0, TimeSpan.FromMinutes(60));

        Assert.True(client.HasPrivateKey);
        AssertEku(client, ClientAuthOid);
        AssertChainsTo(ca, client);
    }

    [Fact]
    public void Leaf_validity_is_clamped_to_the_ca_window()
    {
        using var ca = CertificateAuthority.Create("Short CA", T0, TimeSpan.FromDays(10));
        using var leaf = ca.IssueClientCertificate("x", null, T0, TimeSpan.FromDays(365));

        // The 1-year request is clamped so the leaf cannot outlive the 10-day CA.
        Assert.True(leaf.NotAfter.ToUniversalTime() <= ca.PublicCertificate.NotAfter.ToUniversalTime().AddSeconds(1));
    }

    [Fact]
    public void Leaf_from_a_different_ca_does_not_validate()
    {
        using var ca = NewCa();
        using var otherCa = CertificateAuthority.Create("Rogue CA", T0, TimeSpan.FromDays(365));
        using var foreignLeaf = otherCa.IssueClientCertificate("intruder", null, T0, TimeSpan.FromMinutes(60));

        Assert.False(TryChainTo(ca, foreignLeaf));
    }

    private static void AssertEku(X509Certificate2 certificate, string expectedOid)
    {
        var eku = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().Single();
        Assert.Contains(eku.EnhancedKeyUsages.Cast<System.Security.Cryptography.Oid>(),
            oid => oid.Value == expectedOid);
    }

    private static void AssertChainsTo(CertificateAuthority ca, X509Certificate2 leaf) =>
        Assert.True(TryChainTo(ca, leaf));

    private static bool TryChainTo(CertificateAuthority ca, X509Certificate2 leaf)
    {
        using var caCert = ca.PublicCertificate;
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(caCert);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationTime = T0.AddMinutes(1).UtcDateTime;
        return chain.Build(leaf);
    }
}
