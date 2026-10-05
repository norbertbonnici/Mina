namespace Mina.ControlPlane.Domain.Sessions;

/// <summary>One analyst who has held at least one session, for the browsing-data review picker.</summary>
/// <param name="LastSessionCreatedAt">Used to sort the picker so recently active analysts sort first.</param>
public sealed record AnalystSummary(string UserObjectId, string UserPrincipalName, DateTimeOffset LastSessionCreatedAt);

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

    /// <summary>
    /// One analyst's sessions created within <c>[rangeStart, rangeEnd)</c>, newest first (M3-8:
    /// browsing-data review, scoped to one analyst — no range limit, since the query is already
    /// bounded by identity).
    /// </summary>
    Task<IReadOnlyList<ResearchSession>> ListForAnalystAsync(
        string userObjectId, DateTimeOffset rangeStart, DateTimeOffset rangeEnd, CancellationToken cancellationToken);

    /// <summary>
    /// Every analyst's sessions created within <c>[rangeStart, rangeEnd)</c>, newest first (M3-8).
    /// The caller is responsible for bounding the width of the range — this query has no built-in
    /// ceiling, because "how wide an unscoped query may be" is a policy decision that belongs to the
    /// service enforcing it (<c>BrowsingDataReviewService</c>), not to persistence.
    /// </summary>
    Task<IReadOnlyList<ResearchSession>> ListInRangeAsync(
        DateTimeOffset rangeStart, DateTimeOffset rangeEnd, CancellationToken cancellationToken);

    /// <summary>Distinct analysts who have held a session, most recently active first (M3-8 picker).</summary>
    Task<IReadOnlyList<AnalystSummary>> ListDistinctAnalystsAsync(CancellationToken cancellationToken);
}
