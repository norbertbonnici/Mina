using Microsoft.EntityFrameworkCore;
using Mina.ControlPlane.Domain.Sessions;

namespace Mina.ControlPlane.Persistence;

/// <summary>
/// EF Core-backed session store (ARCHITECTURE §3.2). Sessions are loaded, mutated through the
/// aggregate's own methods, and saved — the concurrency token configured on the entity makes a
/// stale write fail loudly rather than overwrite a newer state.
/// </summary>
public sealed class EfSessionRepository(MinaDbContext context) : ISessionRepository, ISessionQueries
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

    public async Task<IReadOnlyList<ResearchSession>> ListLapsedAsync(
        DateTimeOffset asOf, int limit, CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(limit, 1);

        return await _context.Sessions
            .Where(s => s.State == SessionState.Active && s.LeaseExpiresAt <= asOf)
            .OrderBy(s => s.LeaseExpiresAt)
            .Take(limit)
            .ToListAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<ResearchSession>> ListActiveAsync(
        DateTimeOffset asOf, CancellationToken cancellationToken) =>
        await _context.Sessions
            .Where(s => s.State == SessionState.Active && s.LeaseExpiresAt > asOf)
            .OrderByDescending(s => s.CreatedAt)
            .ToListAsync(cancellationToken).ConfigureAwait(false);

    public async Task<IReadOnlyList<ResearchSession>> ListRecentAsync(
        int limit, CancellationToken cancellationToken) =>
        await _context.Sessions
            .OrderByDescending(s => s.CreatedAt)
            .Take(limit)
            .ToListAsync(cancellationToken).ConfigureAwait(false);

    public async Task<IReadOnlyList<ResearchSession>> ListForAnalystAsync(
        string userObjectId, DateTimeOffset rangeStart, DateTimeOffset rangeEnd, CancellationToken cancellationToken) =>
        await _context.Sessions
            .Where(s => s.UserObjectId == userObjectId && s.CreatedAt >= rangeStart && s.CreatedAt < rangeEnd)
            .OrderByDescending(s => s.CreatedAt)
            .ToListAsync(cancellationToken).ConfigureAwait(false);

    public async Task<IReadOnlyList<ResearchSession>> ListInRangeAsync(
        DateTimeOffset rangeStart, DateTimeOffset rangeEnd, CancellationToken cancellationToken) =>
        await _context.Sessions
            .Where(s => s.CreatedAt >= rangeStart && s.CreatedAt < rangeEnd)
            .OrderByDescending(s => s.CreatedAt)
            .ToListAsync(cancellationToken).ConfigureAwait(false);

    // Grouped by (UserObjectId, UserPrincipalName), not UserObjectId alone: a UPN rename between
    // sessions would then produce two picker entries for the same analyst rather than one. Accepted
    // for M3-8 — Entra UPN renames are rare, and resolving it needs a "latest UPN per object id"
    // query EF cannot translate cleanly, for a display-only inconsistency that a stale-name entry
    // ageing out of the recency-sorted list corrects on its own.
    public async Task<IReadOnlyList<AnalystSummary>> ListDistinctAnalystsAsync(CancellationToken cancellationToken)
    {
        // Grouped/aggregated as an anonymous type, not AnalystSummary directly: no EF Core provider
        // can translate a record's constructor called inside a post-GroupBy Select. Found live
        // 2026-09-07 as an InvalidOperationException ("could not be translated") on the real
        // SQL Server-backed deployment's /browsing-data page -- and confirmed, not assumed, that
        // SQLite fails identically (same exception, same message) once this method actually got a
        // test against a real EF context for the first time. This was never a provider difference:
        // ListDistinctAnalystsAsync had zero coverage against any real EF Core provider before that
        // test existed, only against InMemorySessionRepository's own hand-written LINQ-to-objects
        // implementation, which cannot hit a translation failure by construction. The anonymous-type
        // projection keeps GroupBy/Max/OrderBy translatable server-side; only the final record
        // construction happens client-side, on rows already fetched.
        var grouped = await _context.Sessions
            .GroupBy(s => new { s.UserObjectId, s.UserPrincipalName })
            .Select(g => new { g.Key.UserObjectId, g.Key.UserPrincipalName, LastSessionCreatedAt = g.Max(s => s.CreatedAt) })
            .OrderByDescending(a => a.LastSessionCreatedAt)
            .ToListAsync(cancellationToken).ConfigureAwait(false);

        return grouped
            .Select(g => new AnalystSummary(g.UserObjectId, g.UserPrincipalName, g.LastSessionCreatedAt))
            .ToList();
    }
}
