using Microsoft.EntityFrameworkCore;
using Mina.ControlPlane.Domain.Sessions;

namespace Mina.ControlPlane.Persistence;

/// <summary>
/// EF Core-backed session store (ARCHITECTURE §3.2). Sessions are loaded, mutated through the
/// aggregate's own methods, and saved — the concurrency token configured on the entity makes a
/// stale write fail loudly rather than overwrite a newer state.
/// </summary>
public sealed class EfSessionRepository(MinaDbContext context) : ISessionRepository
{
    private readonly MinaDbContext _context = context ?? throw new ArgumentNullException(nameof(context));

    public async Task AddAsync(ResearchSession session, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);
        await _context.Sessions.AddAsync(session, cancellationToken).ConfigureAwait(false);
        await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<ResearchSession?> FindAsync(Guid id, CancellationToken cancellationToken) =>
        await _context.Sessions.FindAsync([id], cancellationToken).ConfigureAwait(false);

    /// <summary>
    /// Persists changes to a session previously loaded from this repository.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// The instance is not tracked by this context. Saving a detached instance would discard the
    /// concurrency token it was loaded with (the token is a shadow property held by the change
    /// tracker), silently turning a conflicting write into a lost update — so it is refused
    /// instead. Load through <see cref="FindAsync"/>, mutate, then update.
    /// </exception>
    public async Task UpdateAsync(ResearchSession session, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);
        if (_context.Entry(session).State == EntityState.Detached)
        {
            throw new InvalidOperationException(
                "The session is not tracked by this context; load it via FindAsync before updating.");
        }

        await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }
}
