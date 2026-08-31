namespace Mina.ControlPlane.Domain.Sessions;

/// <summary>
/// Persistence for research sessions. The M2-2 implementation is in-memory; the EF Core / Azure
/// SQL implementation (ARCHITECTURE §3.2) is the next step and slots in behind this interface.
/// </summary>
public interface ISessionRepository
{
    Task AddAsync(ResearchSession session, CancellationToken cancellationToken);

    Task<ResearchSession?> FindAsync(Guid id, CancellationToken cancellationToken);

    Task UpdateAsync(ResearchSession session, CancellationToken cancellationToken);
}
