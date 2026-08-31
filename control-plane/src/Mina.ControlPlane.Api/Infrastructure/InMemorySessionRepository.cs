using System.Collections.Concurrent;
using Mina.ControlPlane.Domain.Sessions;

namespace Mina.ControlPlane.Api.Infrastructure;

/// <summary>
/// In-memory session store for M2-2. It is not durable and is per-instance, so it is unsuitable
/// for production; the EF Core / Azure SQL repository (ARCHITECTURE §3.2) replaces it and is the
/// reason <see cref="ISessionRepository"/> exists as a seam.
/// </summary>
public sealed class InMemorySessionRepository : ISessionRepository
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
}
