using Microsoft.EntityFrameworkCore;
using Mina.ControlPlane.Domain.SensitiveSessions;

namespace Mina.ControlPlane.Persistence;

/// <summary>EF Core-backed store for sensitive-session approval records.</summary>
public sealed class EfSensitiveSessionRepository(MinaDbContext context) : ISensitiveSessionRepository
{
    private readonly MinaDbContext _context = context ?? throw new ArgumentNullException(nameof(context));

    public async Task AddAsync(SensitiveSessionRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        await _context.SensitiveSessionRequests.AddAsync(request, cancellationToken).ConfigureAwait(false);
        await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<SensitiveSessionRequest?> FindAsync(Guid id, CancellationToken cancellationToken) =>
        await _context.SensitiveSessionRequests.FindAsync([id], cancellationToken).ConfigureAwait(false);

    /// <inheritdoc />
    /// <exception cref="InvalidOperationException">
    /// The instance is not tracked by this context — see <see cref="EfSessionRepository.UpdateAsync"/>
    /// for why a detached save is refused rather than silently losing the concurrency token.
    /// </exception>
    public async Task UpdateAsync(SensitiveSessionRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (_context.Entry(request).State == EntityState.Detached)
        {
            throw new InvalidOperationException(
                "The request is not tracked by this context; load it via FindAsync before updating.");
        }

        await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<PendingRequestPage> ListPendingAsync(int limit, CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(limit, 1);

        // One more than asked for, so "there is more" is known without a second COUNT. The
        // (State, RequestedAt) index makes this a seek rather than a scan.
        var page = await _context.SensitiveSessionRequests
            .Where(r => r.State == SensitiveSessionState.Requested)
            .OrderBy(r => r.RequestedAt)
            .Take(limit + 1)
            .ToListAsync(cancellationToken).ConfigureAwait(false);

        return page.Count > limit
            ? new PendingRequestPage(page.Take(limit).ToList(), HasMore: true)
            : new PendingRequestPage(page, HasMore: false);
    }

    public async Task<int> CountPendingAsync(CancellationToken cancellationToken) =>
        await _context.SensitiveSessionRequests
            .CountAsync(r => r.State == SensitiveSessionState.Requested, cancellationToken)
            .ConfigureAwait(false);

    public async Task<IReadOnlyList<SensitiveSessionRequest>> ListForSessionAsync(
        Guid sessionId, CancellationToken cancellationToken) =>
        await _context.SensitiveSessionRequests
            .Where(r => r.SessionId == sessionId)
            .OrderByDescending(r => r.RequestedAt)
            .ToListAsync(cancellationToken).ConfigureAwait(false);

    public async Task<IReadOnlyList<SensitiveSessionRequest>> ListExpiredAsync(
        DateTimeOffset asOf, int limit, CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(limit, 1);

        // Oldest first: whatever does not fit in this sweep is the newest, and it is the ones that
        // have been over their window longest that most need ending.
        return await _context.SensitiveSessionRequests
            .Where(r => (r.State == SensitiveSessionState.Approved
                         || r.State == SensitiveSessionState.ActiveSuppressed)
                        && r.ExpiresAt != null && r.ExpiresAt <= asOf)
            .OrderBy(r => r.ExpiresAt)
            .Take(limit)
            .ToListAsync(cancellationToken).ConfigureAwait(false);
    }
}
