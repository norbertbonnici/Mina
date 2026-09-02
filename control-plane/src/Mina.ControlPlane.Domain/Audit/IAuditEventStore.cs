namespace Mina.ControlPlane.Domain.Audit;

/// <summary>Where the tail of the chain currently sits.</summary>
public sealed record AuditChainTip(long Sequence, string Hash)
{
    /// <summary>The tip of an empty chain: the next event takes sequence 0.</summary>
    public static AuditChainTip Empty { get; } = new(-1, AuditEvent.GenesisHash);
}

/// <summary>Result of walking the chain to check it has not been altered.</summary>
/// <param name="Verified">Number of events checked.</param>
/// <param name="BrokenAtSequence">
/// The first event whose recorded hash does not match its contents or does not follow its
/// predecessor, or null if the chain is intact.
/// </param>
public sealed record AuditChainVerification(long Verified, long? BrokenAtSequence, string? Reason)
{
    public bool IsIntact => BrokenAtSequence is null;
}

/// <summary>
/// Append-only store for governance audit events.
/// </summary>
/// <remarks>
/// Implementations must never expose update or delete: the production database grants the control
/// plane INSERT and SELECT on these tables only, so an attempt to rewrite history has to go around
/// the application rather than through it — and the hash chain makes that visible.
/// </remarks>
public interface IAuditEventStore
{
    /// <summary>The current tip, used to chain the next event.</summary>
    Task<AuditChainTip> GetTipAsync(CancellationToken cancellationToken);

    /// <summary>Appends an event. Throws if its sequence has already been taken.</summary>
    Task AppendAsync(AuditEvent auditEvent, CancellationToken cancellationToken);

    /// <summary>Events in chain order, from <paramref name="fromSequence"/> inclusive.</summary>
    Task<IReadOnlyList<AuditEvent>> ReadAsync(
        long fromSequence, int limit, CancellationToken cancellationToken);

    /// <summary>Most recent events first, for the management interface.</summary>
    Task<IReadOnlyList<AuditEvent>> ReadRecentAsync(int limit, CancellationToken cancellationToken);
}
