using System.Collections.Concurrent;
using Mina.ControlPlane.Domain.Telemetry;

namespace Mina.ControlPlane.Persistence;

/// <summary>
/// In-memory telemetry store for local development, paired with the other in-memory repositories.
/// Not durable and not shared between instances.
/// </summary>
public sealed class InMemoryTelemetryRepository : ITelemetryRepository
{
    private readonly ConcurrentBag<HostnameObservation> _hostnames = [];
    private readonly ConcurrentBag<SuppressedTrafficSummary> _suppressed = [];

    public Task AddHostnamesAsync(
        IReadOnlyCollection<HostnameObservation> observations, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(observations);
        foreach (var observation in observations)
        {
            _hostnames.Add(observation);
        }

        return Task.CompletedTask;
    }

    public Task AddSuppressedSummaryAsync(SuppressedTrafficSummary summary, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(summary);
        _suppressed.Add(summary);
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<HostnameObservation>> ListForSessionAsync(
        Guid sessionId, CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<HostnameObservation>>(
            [.. _hostnames.Where(o => o.SessionId == sessionId).OrderByDescending(o => o.OccurredAt)]);

    public Task<IReadOnlyList<SuppressedTrafficSummary>> ListSuppressedForSessionAsync(
        Guid sessionId, CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<SuppressedTrafficSummary>>(
            [.. _suppressed.Where(s => s.SessionId == sessionId).OrderByDescending(s => s.IntervalStart)]);
}
