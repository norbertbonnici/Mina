using System.Security.Cryptography.X509Certificates;
using Azure;
using Azure.Core;
using Azure.Security.KeyVault.Secrets;
using Mina.ControlPlane.Pki;

namespace Mina.ControlPlane.KeyVault;

/// <summary>Names of the two vault objects the internal CA is made of.</summary>
/// <param name="VaultUri">Vault URI — Terraform outputs it as <c>key_vault_uri</c>.</param>
/// <param name="SigningKeyName">The non-exportable EC key that signs. Created by Terraform.</param>
/// <param name="CertificateSecretName">
/// The CA certificate itself, PEM, stored as a secret. Key Vault cannot hold a CA certificate as a
/// <em>certificate</em> — its own certificate objects are always end-entity, with basic constraints
/// asserting cA=false — so the certificate that gives the signing key its authority is kept beside
/// it as a secret and written once by the bootstrap tool. It is public material: everything that
/// trusts this platform holds a copy.
/// </param>
public sealed record KeyVaultCaOptions(
    Uri VaultUri,
    string SigningKeyName = KeyVaultCaOptions.DefaultSigningKeyName,
    string CertificateSecretName = KeyVaultCaOptions.DefaultCertificateSecretName)
{
    public const string DefaultSigningKeyName = "mina-internal-ca";

    public const string DefaultCertificateSecretName = "mina-internal-ca-certificate";
}

/// <summary>
/// Builds the control plane's <see cref="CertificateAuthority"/> from Key Vault: the certificate
/// from a secret, the signing key from the vault's key store, checked against each other.
/// </summary>
public static class KeyVaultCertificateAuthority
{
    /// <summary>
    /// Loads the CA. Throws if the vault is unreachable, if either object is missing, or if the two
    /// do not belong together — all of which are deployment errors that must stop the host rather
    /// than surface later as certificates nothing accepts.
    /// </summary>
    public static async Task<CertificateAuthority> LoadAsync(
        KeyVaultCaOptions options,
        TokenCredential credential,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(credential);

        var signer = await KeyVaultCaSigner
            .CreateAsync(options.VaultUri, options.SigningKeyName, credential, cancellationToken)
            .ConfigureAwait(false);

        var store = new KeyVaultCaCertificateStore(options.VaultUri, credential);
        var certificate = await store
            .TryGetAsync(options.CertificateSecretName, cancellationToken)
            .ConfigureAwait(false)
            ?? throw new InvalidOperationException(
                $"No CA certificate in '{options.VaultUri}' under secret "
                + $"'{options.CertificateSecretName}'. The signing key exists but has never been given a "
                + "certificate: run the bootstrap (control-plane/tools/Mina.Ca, `mina-ca bootstrap`) once "
                + "for this vault.");

        try
        {
            return CertificateAuthority.CreateFromRemoteSigner(certificate, signer);
        }
        catch
        {
            certificate.Dispose();
            throw;
        }
    }
}

/// <summary>Reads and writes the CA certificate held as a Key Vault secret.</summary>
public sealed class KeyVaultCaCertificateStore
{
    private const string PemContentType = "application/x-pem-file";

    private readonly SecretClient _secrets;

    public KeyVaultCaCertificateStore(Uri vaultUri, TokenCredential credential)
    {
        ArgumentNullException.ThrowIfNull(vaultUri);
        ArgumentNullException.ThrowIfNull(credential);

        _secrets = new SecretClient(vaultUri, credential);
    }

    /// <summary>The stored CA certificate, or null when the vault has never been bootstrapped.</summary>
    public async Task<X509Certificate2?> TryGetAsync(
        string secretName, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(secretName);

        try
        {
            var secret = await _secrets.GetSecretAsync(secretName, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            return X509Certificate2.CreateFromPem(secret.Value.Value);
        }
        catch (RequestFailedException missing) when (missing.Status == 404)
        {
            return null;
        }
    }

    /// <summary>
    /// Stores a CA certificate. Refuses to replace one that is already there unless
    /// <paramref name="replaceExisting"/> is set: replacing it re-roots the platform's trust, and
    /// the certificates issued under the old root stop validating the moment nodes reload.
    /// </summary>
    public async Task StoreAsync(
        string secretName,
        X509Certificate2 certificate,
        bool replaceExisting = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(secretName);
        ArgumentNullException.ThrowIfNull(certificate);

        if (!replaceExisting)
        {
            using var existing = await TryGetAsync(secretName, cancellationToken).ConfigureAwait(false);
            if (existing is not null)
            {
                throw new InvalidOperationException(
                    $"Secret '{secretName}' already holds a CA certificate ({existing.Subject}, expires "
                    + $"{existing.NotAfter.ToUniversalTime():u}). Replacing it re-roots every certificate "
                    + "this platform has issued; that is the CA rollover procedure (BACKLOG M4-2), not a "
                    + "bootstrap.");
            }
        }

        var secret = new KeyVaultSecret(secretName, certificate.ExportCertificatePem())
        {
            Properties =
            {
                ContentType = PemContentType,
                ExpiresOn = certificate.NotAfter.ToUniversalTime(),
            },
        };

        await _secrets.SetSecretAsync(secret, cancellationToken).ConfigureAwait(false);
    }
}
