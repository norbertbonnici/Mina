using Microsoft.EntityFrameworkCore;
using Mina.ControlPlane.Domain.Regions;

namespace Mina.ControlPlane.Persistence;

/// <summary>EF Core-backed store for region change requests (ADR-0008 Option C).</summary>
public sealed class EfRegionChangeRequestRepository(MinaDbContext context) : IRegionChangeRequestRepository
{
    private readonly MinaDbContext _context = context ?? throw new ArgumentNullException(nameof(context));

    public async Task AddAsync(RegionChangeRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        await _context.RegionChangeRequests.AddAsync(request, cancellationToken).ConfigureAwait(false);
        await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<RegionChangeRequest?> FindAsync(Guid id, CancellationToken cancellationToken) =>
        await _context.RegionChangeRequests.FindAsync([id], cancellationToken).ConfigureAwait(false);

    /// <inheritdoc />
    /// <exception cref="InvalidOperationException">
    /// The instance is not tracked by this context — see <see cref="EfSessionRepository.UpdateAsync"/>
    /// for why a detached save is refused rather than silently losing the concurrency token.
    /// </exception>
    public async Task UpdateAsync(RegionChangeRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (_context.Entry(request).State == EntityState.Detached)
        {
            throw new InvalidOperationException(
                "The request is not tracked by this context; load it via FindAsync before updating.");
        }

        await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<RegionChangeRequest>> ListPendingAsync(int limit, CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(limit, 1);
        return await _context.RegionChangeRequests
            .Where(r => r.Status == RegionChangeRequestStatus.Pending)
            .OrderBy(r => r.RequestedAt)
            .Take(limit)
            .ToListAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<RegionChangeRequest>> ListRecentlyResolvedAsync(int limit, CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(limit, 1);
        return await _context.RegionChangeRequests
            .Where(r => r.Status != RegionChangeRequestStatus.Pending)
            .OrderByDescending(r => r.ResolvedAt)
            .Take(limit)
            .ToListAsync(cancellationToken).ConfigureAwait(false);
    }
}
