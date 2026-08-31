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
}
