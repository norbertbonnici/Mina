namespace Mina.ControlPlane.Domain.Sessions;

/// <summary>Lifecycle states of a research session (ARCHITECTURE §5, §7).</summary>
public enum SessionState
{
    Active,
    Ended,
    Revoked,
    Expired,
}

/// <summary>Why an <see cref="SessionState.Ended"/> session ended.</summary>
public enum SessionEndReason
{
    EndedByUser,
    BrowserClosed,
    TunnelLost,
}

/// <summary>Logging mode of a session (ADR-0002 / ADR-0003).</summary>
public enum SessionMode
{
    Normal,
    Sensitive,
}

/// <summary>Thrown when a session operation is not valid for the session's current state.</summary>
public sealed class SessionStateException : Exception
{
    public SessionStateException()
    {
    }

    public SessionStateException(string message)
        : base(message)
    {
    }

    public SessionStateException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// A research session and its short lease. The lease is the window a session certificate is
/// valid for; renewal (which the control plane only performs against a fresh Entra token,
/// enforced at the API layer) extends it, and it can never be extended past the CA-bounded
/// certificate lifetime. Loss of the lease means the session must be re-established — bounding
/// the exposure of a stolen session credential (ARCHITECTURE §4).
/// </summary>
public sealed class ResearchSession
{
    private ResearchSession(
        Guid id,
        string userObjectId,
        string userPrincipalName,
        string? deviceId,
        string region,
        DateTimeOffset createdAt,
        DateTimeOffset leaseExpiresAt,
        string certificateSerialNumber)
    {
        Id = id;
        UserObjectId = userObjectId;
        UserPrincipalName = userPrincipalName;
        DeviceId = deviceId;
        Region = region;
        Mode = SessionMode.Normal;
        CreatedAt = createdAt;
        LeaseExpiresAt = leaseExpiresAt;
        CertificateSerialNumber = certificateSerialNumber;
        State = SessionState.Active;
    }

    public Guid Id { get; }

    public string UserObjectId { get; }

    public string UserPrincipalName { get; }

    public string? DeviceId { get; }

    public string Region { get; }

    public SessionMode Mode { get; private set; }

    public DateTimeOffset CreatedAt { get; }

    public DateTimeOffset LeaseExpiresAt { get; private set; }

    public string CertificateSerialNumber { get; private set; }

    public SessionState State { get; private set; }

    public DateTimeOffset? EndedAt { get; private set; }

    public SessionEndReason? EndReason { get; private set; }

    public string? RevokedBy { get; private set; }

    public static ResearchSession Issue(
        Guid id,
        string userObjectId,
        string userPrincipalName,
        string? deviceId,
        string region,
        DateTimeOffset now,
        TimeSpan leaseTtl,
        string certificateSerialNumber)
    {
        if (id == Guid.Empty)
        {
            throw new ArgumentException("A session id is required.", nameof(id));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(userObjectId);
        ArgumentException.ThrowIfNullOrWhiteSpace(userPrincipalName);
        ArgumentException.ThrowIfNullOrWhiteSpace(region);
        ArgumentException.ThrowIfNullOrWhiteSpace(certificateSerialNumber);
        if (leaseTtl <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(leaseTtl), "Lease TTL must be positive.");
        }

        return new ResearchSession(
            id, userObjectId, userPrincipalName, deviceId, region, now, now + leaseTtl, certificateSerialNumber);
    }

    /// <summary>
    /// Renews the lease with a freshly issued certificate. Only valid while the session is active
    /// and its current lease has not lapsed — a lapsed lease requires a new session, not a renewal.
    /// </summary>
    public void Renew(DateTimeOffset now, TimeSpan leaseTtl, string newCertificateSerialNumber)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(newCertificateSerialNumber);
        if (leaseTtl <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(leaseTtl), "Lease TTL must be positive.");
        }

        RequireActive(nameof(Renew));
        if (now >= LeaseExpiresAt)
        {
            throw new SessionStateException("The lease has lapsed; a new session is required.");
        }

        LeaseExpiresAt = now + leaseTtl;
        CertificateSerialNumber = newCertificateSerialNumber;
    }

    public void MarkSensitive()
    {
        RequireActive(nameof(MarkSensitive));
        Mode = SessionMode.Sensitive;
    }

    public void End(DateTimeOffset now, SessionEndReason reason)
    {
        RequireActive(nameof(End));
        State = SessionState.Ended;
        EndedAt = now;
        EndReason = reason;
    }

    public void Revoke(DateTimeOffset now, string revokedBy)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(revokedBy);
        if (State is SessionState.Ended or SessionState.Revoked)
        {
            throw new SessionStateException($"Cannot revoke a session in state {State}.");
        }

        State = SessionState.Revoked;
        EndedAt = now;
        RevokedBy = revokedBy;
    }

    /// <summary>Transitions an active, lapsed session to Expired; returns whether it changed.</summary>
    public bool TryExpire(DateTimeOffset now)
    {
        if (State != SessionState.Active || now < LeaseExpiresAt)
        {
            return false;
        }

        State = SessionState.Expired;
        EndedAt = now;
        return true;
    }

    public bool IsUsableAt(DateTimeOffset now) => State == SessionState.Active && now < LeaseExpiresAt;

    private void RequireActive(string operation)
    {
        if (State != SessionState.Active)
        {
            throw new SessionStateException($"{operation} is not valid for a session in state {State}.");
        }
    }
}
