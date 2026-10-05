namespace Mina.ControlPlane.Domain.Telemetry;

/// <summary>
/// Storage for hostname telemetry. Kept behind its own interface, and in its own tables, because
/// this is a distinct data class (LOGGING_AND_PRIVACY §3 C3) with its own retention and access
/// controls — reading governance audit must not implicitly grant reading browsing destinations.
/// </summary>
public interface ITelemetryRepository
{
    Task AddHostnamesAsync(IReadOnlyCollection<HostnameObservation> observations, CancellationToken cancellationToken);

    Task AddSuppressedSummaryAsync(SuppressedTrafficSummary summary, CancellationToken cancellationToken);

    /// <summary>Hostnames recorded for a session, newest first. Access to this is itself audited.</summary>
    Task<IReadOnlyList<HostnameObservation>> ListForSessionAsync(Guid sessionId, CancellationToken cancellationToken);

    Task<IReadOnlyList<SuppressedTrafficSummary>> ListSuppressedForSessionAsync(
        Guid sessionId, CancellationToken cancellationToken);

    /// <summary>
    /// Hostnames recorded across many sessions at once (M3-8: browsing-data review spans a whole
    /// date range, not one session), newest first. Batched rather than one <see cref="ListForSessionAsync"/>
    /// call per session, so a reviewer's query does not turn into an N+1 round trip per session shown.
    /// </summary>
    Task<IReadOnlyList<HostnameObservation>> ListForSessionsAsync(
        IReadOnlyCollection<Guid> sessionIds, CancellationToken cancellationToken);

    /// <summary>Batched equivalent of <see cref="ListSuppressedForSessionAsync"/> (M3-8).</summary>
    Task<IReadOnlyList<SuppressedTrafficSummary>> ListSuppressedForSessionsAsync(
        IReadOnlyCollection<Guid> sessionIds, CancellationToken cancellationToken);

    /// <summary>
    /// Deletes hostname telemetry recorded before <paramref name="cutoff"/>, returning how many rows
    /// went. C3 retention (LOGGING_AND_PRIVACY §7).
    /// </summary>
    /// <remarks>
    /// This is the one operation in the platform that destroys analyst data on purpose, so it is
    /// bounded and its result is reported rather than assumed: the caller records the count in the
    /// audit trail. Deleting is idempotent, so a second instance running the same sweep removes
    /// nothing and no coordination is needed.
    /// </remarks>
    Task<int> DeleteHostnamesBeforeAsync(DateTimeOffset cutoff, int limit, CancellationToken cancellationToken);

    /// <summary>
    /// Deletes suppressed-traffic summaries recorded before <paramref name="cutoff"/>. Same class
    /// and same window as the hostnames: a summary is what is left of a suppressed session's
    /// traffic, and keeping it longer than the destinations it replaced would be inconsistent.
    /// </summary>
    Task<int> DeleteSuppressedSummariesBeforeAsync(
        DateTimeOffset cutoff, int limit, CancellationToken cancellationToken);
}
