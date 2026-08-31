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
}
