using System.Security.Cryptography.X509Certificates;
using Mina.ControlPlane.Pki;

namespace Mina.ControlPlane.Pki.Tests;

public class SessionCertificateIssuerTests
{
    private static readonly DateTimeOffset T0 = new(2026, 8, 31, 9, 0, 0, TimeSpan.Zero);
    private static readonly SessionCertificatePolicy Policy = new(TimeSpan.FromMinutes(60));

    [Fact]
    public void Issue_embeds_the_session_id_in_subject_and_san_uri()
    {
        var sessionId = Guid.NewGuid();
        using var ca = CertificateAuthority.Create("Mina Test CA", T0, TimeSpan.FromDays(365));
        var issuer = new SessionCertificateIssuer(ca, Policy);

        using var cert = issuer.Issue(sessionId, T0, TimeSpan.FromMinutes(60));

        Assert.Contains(sessionId.ToString("D"), cert.Subject, StringComparison.OrdinalIgnoreCase);
        var san = cert.Extensions.OfType<X509SubjectAlternativeNameExtension>().Single().Format(false);
        Assert.Contains($"mina:session:{sessionId:D}", san, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Issue_respects_the_requested_ttl()
    {
        using var ca = CertificateAuthority.Create("Mina Test CA", T0, TimeSpan.FromDays(365));
        var issuer = new SessionCertificateIssuer(ca, Policy);

        using var cert = issuer.Issue(Guid.NewGuid(), T0, TimeSpan.FromMinutes(45));

        var lifetime = cert.NotAfter.ToUniversalTime() - cert.NotBefore.ToUniversalTime();
        Assert.Equal(45, lifetime.TotalMinutes, precision: 0);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-5)]
    [InlineData(61)] // above the 60-minute policy maximum
    public void Issue_rejects_ttl_outside_policy(int minutes)
    {
        using var ca = CertificateAuthority.Create("Mina Test CA", T0, TimeSpan.FromDays(365));
        var issuer = new SessionCertificateIssuer(ca, Policy);

        Assert.Throws<ArgumentOutOfRangeException>(() =>
            issuer.Issue(Guid.NewGuid(), T0, TimeSpan.FromMinutes(minutes)));
    }

    [Fact]
    public void Issue_rejects_empty_session_id()
    {
        using var ca = CertificateAuthority.Create("Mina Test CA", T0, TimeSpan.FromDays(365));
        var issuer = new SessionCertificateIssuer(ca, Policy);

        Assert.Throws<ArgumentException>(() => issuer.Issue(Guid.Empty, T0, TimeSpan.FromMinutes(30)));
    }
}
