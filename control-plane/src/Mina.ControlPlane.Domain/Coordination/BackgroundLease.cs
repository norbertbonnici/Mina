namespace Mina.ControlPlane.Domain.Coordination;

/// <summary>
/// A time-bounded claim on a piece of singleton background work, held by one control-plane
/// instance at a time.
/// </summary>
/// <remarks>
/// App Service ran one instance, so nothing had to decide what happens when two copies run at once.
/// An on-premises HA pair (ADR-0006) runs everything twice, and the two timers behave differently
/// under duplication: the suppression sweep is safe, because each approval is expired in its own
/// unit of work and the loser of a race gets a concurrency conflict it already handles, while the
/// audit export is not — two instances compute the same range, one loses the write-once race, and
/// the loss is logged and swallowed.
///
/// The first answer to that was a configuration switch designating one instance. This replaces it,
/// because a switch makes failover depend on an operator remembering to move a setting: the
/// instance holding the lease is the one doing the work, and when it stops renewing, another takes
/// over on its own.
///
/// The lease is deliberately short and re-acquired every tick rather than held. An instance that is
/// wedged rather than dead stops renewing and loses the work within one expiry, and a crash needs
/// no unlock step.
/// </remarks>
public sealed class BackgroundLease
{
    private BackgroundLease(string name, string owner, DateTimeOffset expiresAt)
    {
        Name = name;
        Owner = owner;
        ExpiresAt = expiresAt;
    }

    /// <summary>What the lease is for, e.g. <c>audit-export</c>. One row per piece of work.</summary>
    public string Name { get; private set; } = string.Empty;

    /// <summary>Which instance holds it. Opaque; used for renewal and for diagnostics.</summary>
    public string Owner { get; private set; } = string.Empty;

    /// <summary>When the claim lapses if it is not renewed.</summary>
    public DateTimeOffset ExpiresAt { get; private set; }

    public static BackgroundLease Claim(string name, string owner, DateTimeOffset now, TimeSpan ttl)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentException.ThrowIfNullOrWhiteSpace(owner);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(ttl, TimeSpan.Zero);

        return new BackgroundLease(name, owner, now + ttl);
    }

    /// <summary>
    /// Takes or extends the claim, and reports whether the caller now holds it. The holder may
    /// always renew; anybody else may take over only once it has lapsed.
    /// </summary>
    public bool TryTake(string owner, DateTimeOffset now, TimeSpan ttl)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(owner);

        var mine = string.Equals(Owner, owner, StringComparison.Ordinal);
        if (!mine && now < ExpiresAt)
        {
            return false;
        }

        Owner = owner;
        ExpiresAt = now + ttl;
        return true;
    }
}

/// <summary>Where leases live. The store is what makes the claim mutually exclusive.</summary>
public interface IBackgroundLeaseStore
{
    /// <summary>
    /// Attempts to hold <paramref name="name"/> for <paramref name="ttl"/>, returning whether the
    /// caller holds it afterwards.
    /// </summary>
    /// <remarks>
    /// Implementations must make the race safe: two instances calling this at the same instant on a
    /// free lease must not both be told yes. The relational implementation relies on the primary key
    /// plus optimistic concurrency, so the loser sees a conflict rather than a second grant.
    /// </remarks>
    Task<bool> TryAcquireAsync(string name, string owner, TimeSpan ttl, CancellationToken cancellationToken);
}
