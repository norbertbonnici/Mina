using Mina.ControlPlane.Pki;

namespace Mina.ControlPlane.Api.Infrastructure;

/// <summary>Supplies the control plane's issuing CA.</summary>
public interface ICertificateAuthorityProvider
{
    CertificateAuthority GetAuthority();
}

/// <summary>
/// Development CA provider: mints an ephemeral in-memory CA at startup. **Not for production** —
/// the CA is regenerated on every restart, so certificates it issued stop validating, and the
/// key is not protected. Production uses a Key Vault-backed provider whose signing key never
/// leaves the vault (ARCHITECTURE §3.2). This exists so the API runs and is testable without
/// Azure.
/// </summary>
public sealed class DevelopmentCertificateAuthorityProvider : ICertificateAuthorityProvider, IDisposable
{
    private readonly CertificateAuthority _authority =
        CertificateAuthority.Create("Mina Development CA (ephemeral)", DateTimeOffset.UtcNow.AddMinutes(-5), TimeSpan.FromDays(1));

    public CertificateAuthority GetAuthority() => _authority;

    public void Dispose() => _authority.Dispose();
}
