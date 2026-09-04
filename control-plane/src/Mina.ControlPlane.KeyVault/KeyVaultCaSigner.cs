using System.Security.Cryptography;
using Azure.Core;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Mina.ControlPlane.Pki;

namespace Mina.ControlPlane.KeyVault;

/// <summary>
/// The internal CA's signing key, held in Azure Key Vault (SR-005, M2-2c). The key is created in
/// the vault and marked non-exportable, so this process can ask for a signature and cannot ask for
/// the key — which is the entire point of the type.
/// </summary>
/// <remarks>
/// <para>
/// The <em>versioned</em> key identifier is what signs. Key Vault would happily accept the
/// unversioned name and quietly use whatever the current version is, which for a CA is a trap: a
/// rotated key would keep signing certificates that no longer match the CA certificate everything
/// trusts, and nothing would report an error until an analyst's browser failed to connect. Pinning
/// the version means a rotation is a deployment step (the CA rollover procedure, BACKLOG M4-2)
/// rather than a silent change of the root of trust.
/// </para>
/// <para>
/// Every call is one <c>sign</c> operation against the vault, recorded in the Key Vault
/// <c>AuditEvent</c> log the diagnostics settings collect (M4-24). That log is the only place the
/// use of this key is visible outside the control plane's own audit trail.
/// </para>
/// </remarks>
public sealed class KeyVaultCaSigner : IRemoteCaSigner
{
    private readonly CryptographyClient _cryptography;
    private readonly SignatureAlgorithm _algorithm;
    private readonly byte[] _subjectPublicKeyInfo;

    private KeyVaultCaSigner(
        CryptographyClient cryptography,
        SignatureAlgorithm algorithm,
        HashAlgorithmName hashAlgorithm,
        byte[] subjectPublicKeyInfo,
        string keyDescription)
    {
        _cryptography = cryptography;
        _algorithm = algorithm;
        _subjectPublicKeyInfo = subjectPublicKeyInfo;
        HashAlgorithm = hashAlgorithm;
        KeyDescription = keyDescription;
    }

    public ReadOnlyMemory<byte> SubjectPublicKeyInfo => _subjectPublicKeyInfo;

    public HashAlgorithmName HashAlgorithm { get; }

    public string KeyDescription { get; }

    /// <summary>
    /// Reads the key's public half and curve from the vault, and binds this signer to that exact
    /// key version.
    /// </summary>
    public static async Task<KeyVaultCaSigner> CreateAsync(
        Uri vaultUri,
        string keyName,
        TokenCredential credential,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(vaultUri);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyName);
        ArgumentNullException.ThrowIfNull(credential);

        var keys = new KeyClient(vaultUri, credential);
        var key = await keys.GetKeyAsync(keyName, cancellationToken: cancellationToken).ConfigureAwait(false);
        return Create(key.Value, credential);
    }

    internal static KeyVaultCaSigner Create(KeyVaultKey key, TokenCredential credential)
    {
        if (key.KeyType != KeyType.Ec && key.KeyType != KeyType.EcHsm)
        {
            throw new InvalidOperationException(
                $"Key Vault key '{key.Id}' is {key.KeyType}; the internal CA signs with an elliptic-curve key "
                + "(the Terraform module creates an EC P-256 key named mina-internal-ca).");
        }

        var (algorithm, hash) = ForCurve(key.Key.CurveName, key.Id);

        // ToECDsa(false): the public half only. There is no private half to ask for — the key was
        // created in the vault and is not exportable — and asking would need permissions the
        // control plane is deliberately not granted.
        using var publicKey = key.Key.ToECDsa(includePrivateParameters: false);
        var spki = publicKey.ExportSubjectPublicKeyInfo();

        return new KeyVaultCaSigner(
            new CryptographyClient(key.Id, credential), algorithm, hash, spki, key.Id.ToString());
    }

    public byte[] SignHash(ReadOnlySpan<byte> digest, HashAlgorithmName hashAlgorithm)
    {
        if (hashAlgorithm != HashAlgorithm)
        {
            throw new CryptographicException(
                $"Refusing to sign a {hashAlgorithm.Name} digest with {KeyDescription}, which signs "
                + $"{HashAlgorithm.Name}: the digest size must match the key's curve.");
        }

        // Sign, not SignData: only the digest is sent. The vault never sees the certificate.
        var result = _cryptography.Sign(_algorithm, digest.ToArray());
        return result.Signature;
    }

    private static (SignatureAlgorithm Algorithm, HashAlgorithmName Hash) ForCurve(
        KeyCurveName? curve, Uri keyId)
    {
        if (curve == KeyCurveName.P256)
        {
            return (SignatureAlgorithm.ES256, HashAlgorithmName.SHA256);
        }

        if (curve == KeyCurveName.P384)
        {
            return (SignatureAlgorithm.ES384, HashAlgorithmName.SHA384);
        }

        if (curve == KeyCurveName.P521)
        {
            return (SignatureAlgorithm.ES512, HashAlgorithmName.SHA512);
        }

        // P-256K is secp256k1 — valid in Key Vault, not something an X.509 CA in this platform
        // should be using, and refusing it here is cheaper than diagnosing it later.
        throw new InvalidOperationException(
            $"Key Vault key '{keyId}' uses curve '{curve}', which the internal CA does not sign with. "
            + "Use P-256, P-384 or P-521.");
    }
}
