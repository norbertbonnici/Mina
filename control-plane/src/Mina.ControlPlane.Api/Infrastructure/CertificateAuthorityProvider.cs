using Azure.Core;
using Mina.ControlPlane.KeyVault;
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
/// key is not protected. Production uses <see cref="KeyVaultCertificateAuthorityProvider"/>, whose
/// signing key never leaves the vault (ARCHITECTURE §3.2). This exists so the API runs and is
/// testable without Azure.
/// </summary>
public sealed class DevelopmentCertificateAuthorityProvider : ICertificateAuthorityProvider, IDisposable
{
    private readonly CertificateAuthority _authority =
        CertificateAuthority.Create("Mina Development CA (ephemeral)", DateTimeOffset.UtcNow.AddMinutes(-5), TimeSpan.FromDays(1));

    public CertificateAuthority GetAuthority() => _authority;

    public void Dispose() => _authority.Dispose();
}

/// <summary>
/// The production CA (M2-2c, SR-005): certificate and signing key both from Key Vault, the key
/// non-exportable and used only through the vault's sign operation.
/// </summary>
/// <remarks>
/// The CA is loaded once, when this is constructed. Every session certificate then costs one
/// <c>sign</c> call to the vault, which is a network round trip on the session-issuance path —
/// acceptable at ~50 analysts renewing hourly, and the reason issuance is not on any hot path that
/// fans out per request.
/// </remarks>
public sealed class KeyVaultCertificateAuthorityProvider : ICertificateAuthorityProvider, IDisposable
{
    private readonly CertificateAuthority _authority;

    private KeyVaultCertificateAuthorityProvider(CertificateAuthority authority)
    {
        _authority = authority;
    }

    /// <summary>
    /// Loads the CA from the vault, or throws. Synchronous by design: this runs in the composition
    /// root, where the alternative to blocking is starting a host that cannot issue a certificate
    /// and discovering it when an analyst first asks for one.
    /// </summary>
    public static KeyVaultCertificateAuthorityProvider Create(
        KeyVaultCaOptions options, TokenCredential credential) =>
        new(KeyVaultCertificateAuthority.LoadAsync(options, credential).GetAwaiter().GetResult());

    public CertificateAuthority GetAuthority() => _authority;

    public void Dispose() => _authority.Dispose();
}
