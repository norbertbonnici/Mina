using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Mina.ControlPlane.Pki;

/// <summary>
/// A signing key this process can use but cannot read — the shape Key Vault presents (M2-2c,
/// SR-005). The implementation lives with the Azure SDK in the API host; this project stays free
/// of a cloud dependency so the issuance logic can be tested against a local key that behaves the
/// same way.
/// </summary>
/// <remarks>
/// Only a digest ever crosses this interface. The certificate being signed is hashed here and the
/// hash is what the vault sees, so the vault never holds the content of what it signed — which is
/// also why the audit record of key use (Key Vault <c>AuditEvent</c>, M4-24) shows that the key was
/// used, not for what. The control plane's own audit trail is where the "for what" lives.
/// </remarks>
public interface IRemoteCaSigner
{
    /// <summary>DER-encoded SubjectPublicKeyInfo of the signing key — the public half, safe to hold.</summary>
    ReadOnlyMemory<byte> SubjectPublicKeyInfo { get; }

    /// <summary>
    /// The digest algorithm this key signs with. Fixed by the key's curve rather than chosen per
    /// call: an EC key of a given curve has exactly one matching ECDSA digest size, and the remote
    /// signer rejects a mismatch rather than truncating.
    /// </summary>
    HashAlgorithmName HashAlgorithm { get; }

    /// <summary>Identifies the key for logs and error messages (a Key Vault key identifier).</summary>
    string KeyDescription { get; }

    /// <summary>
    /// Signs a digest, returning the raw fixed-width r‖s signature (IEEE P1363) that both Key Vault
    /// and the WebCrypto-style ECDSA APIs produce.
    /// </summary>
    byte[] SignHash(ReadOnlySpan<byte> digest, HashAlgorithmName hashAlgorithm);
}

/// <summary>
/// Bridges <see cref="IRemoteCaSigner"/> to the signature generator
/// <see cref="CertificateRequest"/> uses, so a certificate can be issued by a key this process
/// never holds.
/// </summary>
/// <remarks>
/// The public-key and algorithm-identifier halves are delegated to the framework's own ECDSA
/// generator, built over the public key alone — those two answers depend on the key's curve and the
/// digest, not on possessing the private key, and getting a hand-written AlgorithmIdentifier
/// subtly wrong is a good way to produce certificates that verify here and nowhere else. Only
/// <see cref="SignData"/> is ours, and all it does is hash locally, ask the vault for the
/// signature, and re-encode it.
/// </remarks>
internal sealed class RemoteCaSignatureGenerator : X509SignatureGenerator, IDisposable
{
    private readonly IRemoteCaSigner _signer;
    private readonly ECDsa _publicKey;
    private readonly X509SignatureGenerator _algorithms;

    public RemoteCaSignatureGenerator(IRemoteCaSigner signer)
    {
        ArgumentNullException.ThrowIfNull(signer);

        _signer = signer;
        _publicKey = ECDsa.Create();
        try
        {
            _publicKey.ImportSubjectPublicKeyInfo(signer.SubjectPublicKeyInfo.Span, out _);
            _algorithms = CreateForECDsa(_publicKey);
        }
        catch
        {
            _publicKey.Dispose();
            throw;
        }
    }

    public override byte[] GetSignatureAlgorithmIdentifier(HashAlgorithmName hashAlgorithm) =>
        _algorithms.GetSignatureAlgorithmIdentifier(hashAlgorithm);

    public override byte[] SignData(byte[] data, HashAlgorithmName hashAlgorithm)
    {
        ArgumentNullException.ThrowIfNull(data);

        var digest = Digest(data, hashAlgorithm);
        var signature = _signer.SignHash(digest, hashAlgorithm);
        return ToDerSequence(signature, _signer.KeyDescription);
    }

    protected override PublicKey BuildPublicKey() => _algorithms.PublicKey;

    public void Dispose() => _publicKey.Dispose();

    private static byte[] Digest(byte[] data, HashAlgorithmName hashAlgorithm) => hashAlgorithm.Name switch
    {
        nameof(HashAlgorithmName.SHA256) => SHA256.HashData(data),
        nameof(HashAlgorithmName.SHA384) => SHA384.HashData(data),
        nameof(HashAlgorithmName.SHA512) => SHA512.HashData(data),
        _ => throw new CryptographicException(
            $"Unsupported certificate signature digest '{hashAlgorithm.Name}'; the remote CA signs SHA-256, SHA-384 or SHA-512."),
    };

    /// <summary>
    /// Converts the raw r‖s signature the vault returns into the DER <c>SEQUENCE { r, s }</c> that
    /// X.509 requires. Skipping this produces a certificate whose signature bytes are the right
    /// numbers in the wrong encoding — it is accepted by nothing, including this platform's own
    /// chain building, so it fails loudly rather than silently.
    /// </summary>
    private static byte[] ToDerSequence(byte[] ieeeP1363, string keyDescription)
    {
        if (ieeeP1363 is null || ieeeP1363.Length == 0 || ieeeP1363.Length % 2 != 0)
        {
            throw new CryptographicException(
                $"Remote CA key {keyDescription} returned a {ieeeP1363?.Length ?? 0}-byte ECDSA signature; "
                + "expected an even-length r‖s pair.");
        }

        var half = ieeeP1363.Length / 2;
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteIntegerUnsigned(Minimal(ieeeP1363.AsSpan(0, half)));
            writer.WriteIntegerUnsigned(Minimal(ieeeP1363.AsSpan(half)));
        }

        return writer.Encode();
    }

    /// <summary>
    /// Strips the fixed-width padding. r and s are big-endian integers left-padded to the curve's
    /// field size; DER wants them minimally encoded, and the writer adds back the leading zero byte
    /// itself when the high bit would otherwise read as a negative number.
    /// </summary>
    private static ReadOnlySpan<byte> Minimal(ReadOnlySpan<byte> value)
    {
        var start = 0;
        while (start < value.Length - 1 && value[start] == 0)
        {
            start++;
        }

        return value[start..];
    }
}
