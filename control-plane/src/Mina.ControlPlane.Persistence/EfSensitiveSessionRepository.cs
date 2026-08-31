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

    public async Task<IReadOnlyList<SensitiveSessionRequest>> ListPendingAsync(CancellationToken cancellationToken) =>
        await _context.SensitiveSessionRequests
            .Where(r => r.State == SensitiveSessionState.Requested)
            .OrderBy(r => r.RequestedAt)
            .ToListAsync(cancellationToken).ConfigureAwait(false);

    public async Task<IReadOnlyList<SensitiveSessionRequest>> ListForSessionAsync(
        Guid sessionId, CancellationToken cancellationToken) =>
        await _context.SensitiveSessionRequests
            .Where(r => r.SessionId == sessionId)
            .OrderByDescending(r => r.RequestedAt)
            .ToListAsync(cancellationToken).ConfigureAwait(false);

    public async Task<IReadOnlyList<SensitiveSessionRequest>> ListExpiredAsync(
        DateTimeOffset asOf, CancellationToken cancellationToken) =>
        await _context.SensitiveSessionRequests
            .Where(r => (r.State == SensitiveSessionState.Approved
                         || r.State == SensitiveSessionState.ActiveSuppressed)
                        && r.ExpiresAt != null && r.ExpiresAt <= asOf)
            .ToListAsync(cancellationToken).ConfigureAwait(false);
}
