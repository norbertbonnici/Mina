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

    /// <summary>Requests awaiting an approval decision, oldest first — the approver's queue.</summary>
    Task<IReadOnlyList<SensitiveSessionRequest>> ListPendingAsync(CancellationToken cancellationToken);

    /// <summary>Requests belonging to one research session, newest first.</summary>
    Task<IReadOnlyList<SensitiveSessionRequest>> ListForSessionAsync(
        Guid sessionId, CancellationToken cancellationToken);

    /// <summary>
    /// Approved or actively-suppressed requests whose window has elapsed. The expiry sweeper uses
    /// this to guarantee no approval outlives its TTL (AC-011), even if nothing else touches it.
    /// </summary>
    Task<IReadOnlyList<SensitiveSessionRequest>> ListExpiredAsync(
        DateTimeOffset asOf, CancellationToken cancellationToken);
}
