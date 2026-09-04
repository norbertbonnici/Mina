using Mina.ControlPlane.KeyVault;

namespace Mina.ControlPlane.Api.Configuration;

/// <summary>Approved (D-08) and currently-active egress regions, bound from configuration.</summary>
public sealed class MinaRegionOptions
{
    public const string Section = "Mina:Regions";

    public IList<string> Approved { get; init; } = [];

    public IList<string> Active { get; init; } = [];
}

/// <summary>Egress ingress endpoints per region, bound from configuration.</summary>
public sealed class MinaEgressOptions
{
    public const string Section = "Mina:Egress";

    public IDictionary<string, EgressEndpointConfig> Regions { get; init; } =
        new Dictionary<string, EgressEndpointConfig>(StringComparer.OrdinalIgnoreCase);
}

/// <summary>Config shape for one region's egress ingress.</summary>
public sealed class EgressEndpointConfig
{
    public string Host { get; init; } = string.Empty;

    public int Port { get; init; } = 443;

    public string ServerName { get; init; } = string.Empty;
}

/// <summary>
/// The internal CA's Key Vault objects (M2-2c). Unset means no production CA is configured, which
/// a host that is not Development refuses to start on.
/// </summary>
public sealed class MinaPkiOptions
{
    public const string Section = "Mina:Pki";

    /// <summary>Vault URI — Terraform outputs it as <c>key_vault_uri</c>.</summary>
    public string? KeyVaultUri { get; init; }

    /// <summary>Signing key name; the Terraform module creates <c>mina-internal-ca</c>.</summary>
    public string SigningKeyName { get; init; } = KeyVaultCaOptions.DefaultSigningKeyName;

    /// <summary>Secret holding the CA certificate, written once by <c>mina-ca bootstrap</c>.</summary>
    public string CertificateSecretName { get; init; } = KeyVaultCaOptions.DefaultCertificateSecretName;

    /// <summary>
    /// How long an egress node's own server certificate is valid for (M2-2d). Fixed rather than
    /// client-chosen — a node has no renewal loop of its own yet, unlike a session; rotation is
    /// M4-2. 90 days is a starting point, not a validated production value.
    /// </summary>
    public TimeSpan NodeCertificateLifetime { get; init; } = TimeSpan.FromDays(90);

    public bool IsConfigured => !string.IsNullOrWhiteSpace(KeyVaultUri);

    /// <summary>Validates and converts to the vault-side options, or throws with what is wrong.</summary>
    public KeyVaultCaOptions ToKeyVaultOptions()
    {
        if (!IsConfigured)
        {
            throw new InvalidOperationException($"{Section}:KeyVaultUri is not configured.");
        }

        if (!Uri.TryCreate(KeyVaultUri, UriKind.Absolute, out var vaultUri)
            || vaultUri.Scheme != Uri.UriSchemeHttps)
        {
            throw new InvalidOperationException(
                $"{Section}:KeyVaultUri must be an absolute https URI "
                + $"(https://<vault>.vault.azure.net/); found '{KeyVaultUri}'.");
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(SigningKeyName);
        ArgumentException.ThrowIfNullOrWhiteSpace(CertificateSecretName);

        return new KeyVaultCaOptions(vaultUri, SigningKeyName, CertificateSecretName);
    }
}
