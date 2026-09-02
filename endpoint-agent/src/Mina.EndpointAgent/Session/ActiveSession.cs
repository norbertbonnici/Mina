using Mina.EndpointAgent.Proxy;

namespace Mina.EndpointAgent.Session;

/// <summary>
/// A live research session: the lease the control plane granted, and the authenticated tunnel it
/// authorises. While no instance of this exists, the agent has no path to the internet for the
/// research browser — which is what makes the protected path fail closed.
/// </summary>
public sealed class ActiveSession : IResearchSession, IDisposable
{
    private readonly SessionKeyMaterial _keyMaterial;

    internal ActiveSession(SessionGrantResponse grant, SessionKeyMaterial keyMaterial, ITunnelConnectionFactory tunnel)
    {
        SessionId = grant.SessionId;
        Region = grant.Region;
        CertificateSerialNumber = grant.CertificateSerialNumber;
        LeaseExpiresAt = grant.LeaseExpiresAt;
        Mode = grant.Mode;
        _keyMaterial = keyMaterial;
        Tunnel = tunnel;
    }

    public Guid SessionId { get; }

    public string Region { get; }

    public string CertificateSerialNumber { get; }

    public DateTimeOffset LeaseExpiresAt { get; }

    /// <summary>Logging mode reported by the control plane ("Normal" or "Sensitive", FR-006).</summary>
    public string Mode { get; }

    internal ITunnelConnectionFactory Tunnel { get; }

    public bool IsDueForRenewal(DateTimeOffset now, TimeSpan margin) => now >= LeaseExpiresAt - margin;

    public bool HasLapsed(DateTimeOffset now) => now >= LeaseExpiresAt;

    public void Dispose() => _keyMaterial.Dispose();
}
