using System.Collections.Concurrent;
using Mina.ControlPlane.Domain.SensitiveSessions;

namespace Mina.ControlPlane.Persistence;

/// <summary>
/// In-memory approval store for local development, paired with
/// <see cref="InMemorySessionRepository"/>. Not durable and not shared between instances — the EF
/// repository is used whenever a connection string is configured.
/// </summary>
public sealed class InMemorySensitiveSessionRepository : ISensitiveSessionRepository
{
    private readonly ConcurrentDictionary<Guid, SensitiveSessionRequest> _requests = new();

    public Task AddAsync(SensitiveSessionRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        _requests[request.Id] = request;
        return Task.CompletedTask;
    }

    public Task<SensitiveSessionRequest?> FindAsync(Guid id, CancellationToken cancellationToken) =>
        Task.FromResult(_requests.GetValueOrDefault(id));

    public Task UpdateAsync(SensitiveSessionRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        _requests[request.Id] = request;
        return Task.CompletedTask;
    }

    public Task<PendingRequestPage> ListPendingAsync(int limit, CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(limit, 1);
        var page = _requests.Values
            .Where(r => r.State == SensitiveSessionState.Requested)
            .OrderBy(r => r.RequestedAt)
            .Take(limit + 1)
            .ToList();

        return Task.FromResult(page.Count > limit
            ? new PendingRequestPage(page.Take(limit).ToList(), HasMore: true)
            : new PendingRequestPage(page, HasMore: false));
    }

    public Task<int> CountPendingAsync(CancellationToken cancellationToken) =>
        Task.FromResult(_requests.Values.Count(r => r.State == SensitiveSessionState.Requested));

    public Task<IReadOnlyList<SensitiveSessionRequest>> ListForSessionAsync(
        Guid sessionId, CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<SensitiveSessionRequest>>(
            [.. _requests.Values
                .Where(r => r.SessionId == sessionId)
                .OrderByDescending(r => r.RequestedAt)]);

    public Task<IReadOnlyList<SensitiveSessionRequest>> ListExpiredAsync(
        DateTimeOffset asOf, int limit, CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(limit, 1);
        return Task.FromResult<IReadOnlyList<SensitiveSessionRequest>>(
            [.. _requests.Values
                .Where(r => r.State is SensitiveSessionState.Approved or SensitiveSessionState.ActiveSuppressed
                            && r.ExpiresAt is not null && r.ExpiresAt <= asOf)
                .OrderBy(r => r.ExpiresAt)
                .Take(limit)]);
    }
}
