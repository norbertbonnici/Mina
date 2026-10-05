namespace Mina.EgressNode.Sidecar;

/// <summary>
/// Reads a session id from the principal Envoy reports for a verified client certificate.
/// </summary>
/// <remarks>
/// Envoy sets the principal from the peer certificate's first URI SAN, falling back to a DNS SAN
/// or the subject when there is none. The internal CA issues exactly one URI SAN per session
/// certificate, <c>mina:session:&lt;id&gt;</c>, so anything else — a DNS name, a subject, a
/// foreign URI scheme, a malformed id — is a certificate that was not issued as designed, and the
/// answer is null. The caller treats null as a refusal; there is no lenient path.
/// </remarks>
public static class SessionPrincipal
{
    public const string Prefix = "mina:session:";

    public static Guid? TryParse(string? principal)
    {
        if (string.IsNullOrEmpty(principal) || !principal.StartsWith(Prefix, StringComparison.Ordinal))
        {
            return null;
        }

        // Exact "D" form only: no braces, no trailing characters, no case games.
        return Guid.TryParseExact(principal.AsSpan(Prefix.Length), "D", out var id) && id != Guid.Empty
            ? id
            : null;
    }
}
