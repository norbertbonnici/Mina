using Mina.ControlPlane.Domain.Telemetry;

namespace Mina.ControlPlane.Persistence;

/// <summary>
/// In-memory telemetry store for local development, paired with the other in-memory repositories.
/// Not durable and not shared between instances.
/// </summary>
/// <remarks>
/// Plain lists under a lock rather than concurrent collections: retention has to remove items, and
/// <see cref="System.Collections.Concurrent.ConcurrentBag{T}"/> cannot. Contention is irrelevant at
/// the scale this store is for.
/// </remarks>
public sealed class InMemoryTelemetryRepository : ITelemetryRepository
{
    private readonly Lock _gate = new();
    private readonly List<HostnameObservation> _hostnames = [];
    private readonly List<SuppressedTrafficSummary> _suppressed = [];

    public Task AddHostnamesAsync(
        IReadOnlyCollection<HostnameObservation> observations, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(observations);
        lock (_gate)
        {
            _hostnames.AddRange(observations);
        }

        return Task.CompletedTask;
    }

    public Task AddSuppressedSummaryAsync(SuppressedTrafficSummary summary, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(summary);
        lock (_gate)
        {
            _suppressed.Add(summary);
        }

        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<HostnameObservation>> ListForSessionAsync(
        Guid sessionId, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            return Task.FromResult<IReadOnlyList<HostnameObservation>>(
                [.. _hostnames.Where(o => o.SessionId == sessionId).OrderByDescending(o => o.OccurredAt)]);
        }
    }

    public Task<IReadOnlyList<SuppressedTrafficSummary>> ListSuppressedForSessionAsync(
        Guid sessionId, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            return Task.FromResult<IReadOnlyList<SuppressedTrafficSummary>>(
                [.. _suppressed.Where(s => s.SessionId == sessionId).OrderByDescending(s => s.IntervalStart)]);
        }
    }

    public Task<IReadOnlyList<HostnameObservation>> ListForSessionsAsync(
        IReadOnlyCollection<Guid> sessionIds, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(sessionIds);
        lock (_gate)
        {
            return Task.FromResult<IReadOnlyList<HostnameObservation>>(
                [.. _hostnames.Where(o => sessionIds.Contains(o.SessionId)).OrderByDescending(o => o.OccurredAt)]);
        }
    }

    public Task<IReadOnlyList<SuppressedTrafficSummary>> ListSuppressedForSessionsAsync(
        IReadOnlyCollection<Guid> sessionIds, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(sessionIds);
        lock (_gate)
        {
            return Task.FromResult<IReadOnlyList<SuppressedTrafficSummary>>(
                [.. _suppressed.Where(s => sessionIds.Contains(s.SessionId)).OrderByDescending(s => s.IntervalStart)]);
        }
    }

    public Task<int> DeleteHostnamesBeforeAsync(
        DateTimeOffset cutoff, int limit, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            return Task.FromResult(Remove(_hostnames, o => o.OccurredAt, cutoff, limit));
        }
    }

    public Task<int> DeleteSuppressedSummariesBeforeAsync(
        DateTimeOffset cutoff, int limit, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            return Task.FromResult(Remove(_suppressed, s => s.IntervalStart, cutoff, limit));
        }
    }

    private static int Remove<T>(
        List<T> items, Func<T, DateTimeOffset> timestamp, DateTimeOffset cutoff, int limit)
    {
        var doomed = items
            .Where(i => timestamp(i) < cutoff)
            .OrderBy(timestamp)
            .Take(limit)
            .ToList();

        foreach (var item in doomed)
        {
            items.Remove(item);
        }

        return doomed.Count;
    }
}
