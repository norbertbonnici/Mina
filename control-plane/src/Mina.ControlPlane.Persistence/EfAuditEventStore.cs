using Microsoft.EntityFrameworkCore;
using Mina.ControlPlane.Domain.Audit;

namespace Mina.ControlPlane.Persistence;

/// <summary>EF Core-backed append-only audit store.</summary>
public sealed class EfAuditEventStore(MinaDbContext context) : IAuditEventStore
{
    private readonly MinaDbContext _context = context ?? throw new ArgumentNullException(nameof(context));

    public async Task<AuditChainTip> GetTipAsync(CancellationToken cancellationToken)
    {
        var tip = await _context.AuditEvents
            .OrderByDescending(e => e.Sequence)
            .Select(e => new { e.Sequence, e.Hash })
            .FirstOrDefaultAsync(cancellationToken).ConfigureAwait(false);

        return tip is null ? AuditChainTip.Empty : new AuditChainTip(tip.Sequence, tip.Hash);
    }

    public async Task AppendAsync(AuditEvent auditEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(auditEvent);
        await _context.AuditEvents.AddAsync(auditEvent, cancellationToken).ConfigureAwait(false);
        try
        {
            await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (DbUpdateException ex)
        {
            // The unique sequence index rejected it: another writer took this position. Detach so
            // the context is reusable, and let the caller re-read the tip and try again.
            _context.Entry(auditEvent).State = EntityState.Detached;
            throw new AuditSequenceConflictException("The audit sequence was taken by another writer.", ex);
        }
    }

    public async Task<IReadOnlyList<AuditEvent>> ReadAsync(
        long fromSequence, int limit, CancellationToken cancellationToken) =>
        await _context.AuditEvents
            .Where(e => e.Sequence >= fromSequence)
            .OrderBy(e => e.Sequence)
            .Take(limit)
            .ToListAsync(cancellationToken).ConfigureAwait(false);

    public async Task<IReadOnlyList<AuditEvent>> ReadRecentAsync(int limit, CancellationToken cancellationToken) =>
        await _context.AuditEvents
            .OrderByDescending(e => e.Sequence)
            .Take(limit)
            .ToListAsync(cancellationToken).ConfigureAwait(false);
}
