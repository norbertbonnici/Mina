using Microsoft.EntityFrameworkCore;
using Mina.ControlPlane.Domain.Telemetry;

namespace Mina.ControlPlane.Persistence;

/// <summary>EF Core-backed store for hostname telemetry (data class C3).</summary>
public sealed class EfTelemetryRepository(MinaDbContext context) : ITelemetryRepository
{
    private readonly MinaDbContext _context = context ?? throw new ArgumentNullException(nameof(context));

    public async Task AddHostnamesAsync(
        IReadOnlyCollection<HostnameObservation> observations, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(observations);
        if (observations.Count == 0)
        {
            return;
        }

        await _context.Hostnames.AddRangeAsync(observations, cancellationToken).ConfigureAwait(false);
        await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task AddSuppressedSummaryAsync(SuppressedTrafficSummary summary, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(summary);
        await _context.SuppressedTraffic.AddAsync(summary, cancellationToken).ConfigureAwait(false);
        await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<HostnameObservation>> ListForSessionAsync(
        Guid sessionId, CancellationToken cancellationToken) =>
        await _context.Hostnames
            .Where(o => o.SessionId == sessionId)
            .OrderByDescending(o => o.OccurredAt)
            .ToListAsync(cancellationToken).ConfigureAwait(false);

    public async Task<IReadOnlyList<SuppressedTrafficSummary>> ListSuppressedForSessionAsync(
        Guid sessionId, CancellationToken cancellationToken) =>
        await _context.SuppressedTraffic
            .Where(s => s.SessionId == sessionId)
            .OrderByDescending(s => s.IntervalStart)
            .ToListAsync(cancellationToken).ConfigureAwait(false);

    public async Task<IReadOnlyList<HostnameObservation>> ListForSessionsAsync(
        IReadOnlyCollection<Guid> sessionIds, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(sessionIds);
        if (sessionIds.Count == 0)
        {
            return [];
        }

        return await _context.Hostnames
            .Where(o => sessionIds.Contains(o.SessionId))
            .OrderByDescending(o => o.OccurredAt)
            .ToListAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<SuppressedTrafficSummary>> ListSuppressedForSessionsAsync(
        IReadOnlyCollection<Guid> sessionIds, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(sessionIds);
        if (sessionIds.Count == 0)
        {
            return [];
        }

        return await _context.SuppressedTraffic
            .Where(s => sessionIds.Contains(s.SessionId))
            .OrderByDescending(s => s.IntervalStart)
            .ToListAsync(cancellationToken).ConfigureAwait(false);
    }

    // ExecuteDelete, not load-then-remove: retention runs against a table sized by every destination
    // every analyst has reached, and materialising a batch only to delete it doubles the work for
    // rows nobody reads. Oldest first, so a bounded pass always makes progress on the oldest data
    // rather than deleting an arbitrary slice of what is expired.
    public Task<int> DeleteHostnamesBeforeAsync(
        DateTimeOffset cutoff, int limit, CancellationToken cancellationToken) =>
        _context.Hostnames
            .Where(o => o.OccurredAt < cutoff)
            .OrderBy(o => o.OccurredAt)
            .Take(limit)
            .ExecuteDeleteAsync(cancellationToken);

    public Task<int> DeleteSuppressedSummariesBeforeAsync(
        DateTimeOffset cutoff, int limit, CancellationToken cancellationToken) =>
        _context.SuppressedTraffic
            .Where(s => s.IntervalStart < cutoff)
            .OrderBy(s => s.IntervalStart)
            .Take(limit)
            .ExecuteDeleteAsync(cancellationToken);
}
