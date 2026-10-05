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
            // Detach either way, so the context is reusable: an audit failure must not leave a
            // half-applied event tracked for the next SaveChanges to pick up.
            _context.Entry(auditEvent).State = EntityState.Detached;

            var taken = await AuditConflictClassifier
                .IsSequenceTakenAsync(_context, auditEvent.Sequence, cancellationToken).ConfigureAwait(false);

            if (!taken)
            {
                // A real database fault. Reporting it as a sequence conflict would send it round
                // the writer's retry loop — five attempts against a database that is not going to
                // recover — and then name the wrong cause in the failure the caller sees. The
                // action still does not proceed: the caller treats any append failure as fatal.
                throw;
            }

            // The unique sequence index rejected it: another writer took this position. Let the
            // caller re-read the tip and try again.
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
