using System.Security.Cryptography.X509Certificates;

namespace Mina.ControlPlane.Pki;

/// <summary>Bounds on session client-certificate lifetimes (ARCHITECTURE §4 session lease model).</summary>
/// <param name="MaxTtl">Upper bound on a session certificate's validity (e.g. 60 minutes).</param>
public sealed record SessionCertificatePolicy(TimeSpan MaxTtl)
{
    public bool IsWithinLimit(TimeSpan ttl) => ttl > TimeSpan.Zero && ttl <= MaxTtl;
}

/// <summary>
/// Issues short-lived client certificates bound to a research session. The certificate carries
/// the session id in both its subject and a SAN URI (<c>mina:session:{id}</c>) so an egress
/// node can authenticate and attribute a tunnel to a specific session without a directory
/// lookup. Renewal issues a fresh certificate; there is no long-lived client credential.
/// </summary>
public sealed class SessionCertificateIssuer(CertificateAuthority authority, SessionCertificatePolicy policy)
{
    public const string SessionUriScheme = "mina";

    private readonly CertificateAuthority _authority =
        authority ?? throw new ArgumentNullException(nameof(authority));

    private readonly SessionCertificatePolicy _policy =
        policy ?? throw new ArgumentNullException(nameof(policy));

    public static string SessionUri(Guid sessionId) => $"{SessionUriScheme}:session:{sessionId:D}";

    public X509Certificate2 Issue(Guid sessionId, DateTimeOffset now, TimeSpan ttl)
    {
        if (sessionId == Guid.Empty)
        {
            throw new ArgumentException("A session id is required.", nameof(sessionId));
        }

        if (!_policy.IsWithinLimit(ttl))
        {
            throw new ArgumentOutOfRangeException(
                nameof(ttl), $"Session certificate TTL must be positive and at most {_policy.MaxTtl}.");
        }

        return _authority.IssueClientCertificate(
            commonName: $"mina-session-{sessionId:D}",
            sessionUri: SessionUri(sessionId),
            notBefore: now,
            lifetime: ttl);
    }
}
