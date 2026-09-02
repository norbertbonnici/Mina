using Microsoft.EntityFrameworkCore;
using Mina.ControlPlane.Domain.Coordination;

namespace Mina.ControlPlane.Persistence;

/// <summary>
/// Relational lease store. Mutual exclusion comes from the database rather than from anything in
/// this process: the primary key stops two instances inserting the same lease, and the concurrency
/// token stops two instances taking over the same lapsed one.
/// </summary>
public sealed class EfBackgroundLeaseStore(MinaDbContext context, TimeProvider clock) : IBackgroundLeaseStore
{
    private readonly MinaDbContext _context = context ?? throw new ArgumentNullException(nameof(context));
    private readonly TimeProvider _clock = clock ?? throw new ArgumentNullException(nameof(clock));

    public async Task<bool> TryAcquireAsync(
        string name, string owner, TimeSpan ttl, CancellationToken cancellationToken)
    {
        var now = _clock.GetUtcNow();
        var existing = await _context.BackgroundLeases
            .FirstOrDefaultAsync(l => l.Name == name, cancellationToken).ConfigureAwait(false);

        try
        {
            if (existing is null)
            {
                await _context.BackgroundLeases
                    .AddAsync(BackgroundLease.Claim(name, owner, now, ttl), cancellationToken)
                    .ConfigureAwait(false);
            }
            else if (!existing.TryTake(owner, now, ttl))
            {
                // Held by somebody else and not yet lapsed. Nothing to write.
                return false;
            }

            await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            return true;
        }
        catch (DbUpdateException)
        {
            // Lost the race — another instance inserted the row or renewed it between the read and
            // the write. Losing is an ordinary outcome here, not a fault: the other instance is
            // doing the work, and this one tries again on its next tick.
            _context.ChangeTracker.Clear();
            return false;
        }
    }
}

/// <summary>
/// Single-process lease store for local development, where there is nothing to contend with.
/// </summary>
/// <remarks>
/// Always grants. That is correct for one process and wrong for two, which is why the composition
/// root only selects it alongside the other in-memory stores — and refuses to start on those
/// outside Development.
/// </remarks>
public sealed class AlwaysGrantedLeaseStore : IBackgroundLeaseStore
{
    public Task<bool> TryAcquireAsync(
        string name, string owner, TimeSpan ttl, CancellationToken cancellationToken) =>
        Task.FromResult(true);
}
