using System.Collections.Concurrent;
using Mina.ControlPlane.Domain.SensitiveSessions;

namespace Mina.ControlPlane.Api.Infrastructure;

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

    public Task<IReadOnlyList<SensitiveSessionRequest>> ListPendingAsync(CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<SensitiveSessionRequest>>(
            [.. _requests.Values
                .Where(r => r.State == SensitiveSessionState.Requested)
                .OrderBy(r => r.RequestedAt)]);

    public Task<IReadOnlyList<SensitiveSessionRequest>> ListForSessionAsync(
        Guid sessionId, CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<SensitiveSessionRequest>>(
            [.. _requests.Values
                .Where(r => r.SessionId == sessionId)
                .OrderByDescending(r => r.RequestedAt)]);

    public Task<IReadOnlyList<SensitiveSessionRequest>> ListExpiredAsync(
        DateTimeOffset asOf, CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<SensitiveSessionRequest>>(
            [.. _requests.Values.Where(r =>
                r.State is SensitiveSessionState.Approved or SensitiveSessionState.ActiveSuppressed
                && r.ExpiresAt is not null && r.ExpiresAt <= asOf)]);
}
