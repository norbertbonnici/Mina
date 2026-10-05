using System.Collections.Concurrent;
using Mina.ControlPlane.Domain.Sessions;

namespace Mina.ControlPlane.Persistence;

/// <summary>
/// In-memory session store for M2-2. It is not durable and is per-instance, so it is unsuitable
/// for production; the EF Core / Azure SQL repository (ARCHITECTURE §3.2) replaces it and is the
/// reason <see cref="ISessionRepository"/> exists as a seam.
/// </summary>
public sealed class InMemorySessionRepository : ISessionRepository, ISessionQueries
{
    private readonly ConcurrentDictionary<Guid, ResearchSession> _sessions = new();

    public Task AddAsync(ResearchSession session, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);
        _sessions[session.Id] = session;
        return Task.CompletedTask;
    }

    public Task<ResearchSession?> FindAsync(Guid id, CancellationToken cancellationToken) =>
        Task.FromResult(_sessions.GetValueOrDefault(id));

    public Task UpdateAsync(ResearchSession session, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);
        _sessions[session.Id] = session;
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<ResearchSession>> ListLapsedAsync(
        DateTimeOffset asOf, int limit, CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(limit, 1);
        return Task.FromResult<IReadOnlyList<ResearchSession>>(
            [.. _sessions.Values
                .Where(s => s.State == SessionState.Active && s.LeaseExpiresAt <= asOf)
                .OrderBy(s => s.LeaseExpiresAt)
                .Take(limit)]);
    }

    public Task<IReadOnlyList<ResearchSession>> ListActiveAsync(
        DateTimeOffset asOf, CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<ResearchSession>>(
            [.. _sessions.Values.Where(s => s.IsUsableAt(asOf)).OrderByDescending(s => s.CreatedAt)]);

    public Task<IReadOnlyList<ResearchSession>> ListRecentAsync(int limit, CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<ResearchSession>>(
            [.. _sessions.Values.OrderByDescending(s => s.CreatedAt).Take(limit)]);

    public Task<IReadOnlyList<ResearchSession>> ListForAnalystAsync(
        string userObjectId, DateTimeOffset rangeStart, DateTimeOffset rangeEnd, CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<ResearchSession>>(
            [.. _sessions.Values
                .Where(s => s.UserObjectId == userObjectId && s.CreatedAt >= rangeStart && s.CreatedAt < rangeEnd)
                .OrderByDescending(s => s.CreatedAt)]);

    public Task<IReadOnlyList<ResearchSession>> ListInRangeAsync(
        DateTimeOffset rangeStart, DateTimeOffset rangeEnd, CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<ResearchSession>>(
            [.. _sessions.Values
                .Where(s => s.CreatedAt >= rangeStart && s.CreatedAt < rangeEnd)
                .OrderByDescending(s => s.CreatedAt)]);

    public Task<IReadOnlyList<AnalystSummary>> ListDistinctAnalystsAsync(CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<AnalystSummary>>(
            [.. _sessions.Values
                .GroupBy(s => (s.UserObjectId, s.UserPrincipalName))
                .Select(g => new AnalystSummary(g.Key.UserObjectId, g.Key.UserPrincipalName, g.Max(s => s.CreatedAt)))
                .OrderByDescending(a => a.LastSessionCreatedAt)]);
}
