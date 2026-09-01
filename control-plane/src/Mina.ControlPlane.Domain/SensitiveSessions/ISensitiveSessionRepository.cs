namespace Mina.ControlPlane.Domain.SensitiveSessions;

/// <summary>Persistence for sensitive-session requests (the approval record set).</summary>
public interface ISensitiveSessionRepository
{
    Task AddAsync(SensitiveSessionRequest request, CancellationToken cancellationToken);

    Task<SensitiveSessionRequest?> FindAsync(Guid id, CancellationToken cancellationToken);

    /// <summary>
    /// Persists changes to a request. As with sessions, the instance must be one this repository
    /// returned within the same unit of work.
    /// </summary>
    Task UpdateAsync(SensitiveSessionRequest request, CancellationToken cancellationToken);

    /// <summary>
    /// Requests awaiting an approval decision, oldest first — the approver's queue. Bounded,
    /// because an analyst can lengthen it at will and an unbounded read of it is a query whose size
    /// an ordinary user controls. It is not the only one: the active-session set behind
    /// <c>ISessionQueries.ListActiveAsync</c> is also analyst-driven and still unbounded, and grows
    /// without limit while nothing sweeps lapsed leases (backlog M4-12).
    /// </summary>
    /// <param name="limit">
    /// Maximum requests to return. Implementations read one more than this so the caller can tell
    /// a full page from a truncated one — a queue that silently stops at N would let a flood push a
    /// genuine request out of sight of the approver, which is worse than the memory problem.
    /// </param>
    Task<PendingRequestPage> ListPendingAsync(int limit, CancellationToken cancellationToken);

    /// <summary>How many requests are awaiting a decision. A count, not a materialised list.</summary>
    Task<int> CountPendingAsync(CancellationToken cancellationToken);

    /// <summary>Requests belonging to one research session, newest first.</summary>
    Task<IReadOnlyList<SensitiveSessionRequest>> ListForSessionAsync(
        Guid sessionId, CancellationToken cancellationToken);

    /// <summary>
    /// Approved or actively-suppressed requests whose window has elapsed. The expiry sweeper uses
    /// this to guarantee no approval outlives its TTL (AC-011), even if nothing else touches it.
    /// </summary>
    /// <param name="limit">
    /// Maximum to return in one sweep. Bounded so a backlog — after an outage, say — is worked
    /// through in batches rather than loaded at once; the sweeper runs again in 30 seconds, so
    /// nothing is left behind, and each expiry is already independent of the others.
    /// </param>
    Task<IReadOnlyList<SensitiveSessionRequest>> ListExpiredAsync(
        DateTimeOffset asOf, int limit, CancellationToken cancellationToken);
}

/// <summary>
/// One page of the approver queue, and whether there is more behind it.
/// </summary>
/// <param name="Requests">Up to the requested limit, oldest first.</param>
/// <param name="HasMore">
/// True when the queue is longer than the page. Reported rather than hidden: an approver deciding
/// suppression needs to know they are not looking at everything.
/// </param>
public sealed record PendingRequestPage(IReadOnlyList<SensitiveSessionRequest> Requests, bool HasMore);
