namespace Mina.ControlPlane.Domain.Sessions;

/// <summary>
/// Read-only views over sessions for the management interface (FR-013). Kept separate from
/// <see cref="ISessionRepository"/> so the write path stays a narrow, aggregate-at-a-time contract.
/// </summary>
public interface ISessionQueries
{
    /// <summary>Sessions that are currently usable, newest first.</summary>
    Task<IReadOnlyList<ResearchSession>> ListActiveAsync(DateTimeOffset asOf, CancellationToken cancellationToken);

    /// <summary>The most recent sessions in any state, newest first.</summary>
    Task<IReadOnlyList<ResearchSession>> ListRecentAsync(int limit, CancellationToken cancellationToken);
}
