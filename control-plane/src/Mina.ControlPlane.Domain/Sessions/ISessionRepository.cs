namespace Mina.ControlPlane.Domain.Sessions;

/// <summary>
/// Persistence for research sessions. The M2-2 implementation is in-memory; the EF Core / Azure
/// SQL implementation (ARCHITECTURE §3.2) is the next step and slots in behind this interface.
/// </summary>
public interface ISessionRepository
{
    Task AddAsync(ResearchSession session, CancellationToken cancellationToken);

    Task<ResearchSession?> FindAsync(Guid id, CancellationToken cancellationToken);

    /// <summary>
    /// Persists changes to a session. The instance must be one this repository returned from
    /// <see cref="FindAsync"/> within the same unit of work: implementations may rely on that to
    /// detect concurrent modification, and may reject an instance obtained elsewhere.
    /// </summary>
    Task UpdateAsync(ResearchSession session, CancellationToken cancellationToken);

    /// <summary>
    /// Active sessions whose lease has elapsed, oldest first — the expiry sweeper's queue.
    /// </summary>
    /// <remarks>
    /// A lapsed session is already unusable: <see cref="ResearchSession.IsUsableAt"/> checks the
    /// lease, so nothing can be renewed or activated on it. What it is not is *finished*. Until
    /// something sweeps it, the row stays <see cref="SessionState.Active"/> for ever, no terminal
    /// event is written, and every query that reasons about active sessions — the node allowlist
    /// among them — keeps returning sessions that died hours ago.
    /// </remarks>
    /// <param name="limit">
    /// Bounded for the same reason the suppression sweep is: an outage produces a backlog, and the
    /// sweeper runs again shortly. Working through it in batches is preferable to one unbounded read.
    /// </param>
    Task<IReadOnlyList<ResearchSession>> ListLapsedAsync(
        DateTimeOffset asOf, int limit, CancellationToken cancellationToken);
}
