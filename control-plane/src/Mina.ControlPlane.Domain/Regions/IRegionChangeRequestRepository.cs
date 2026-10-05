namespace Mina.ControlPlane.Domain.Regions;

/// <summary>Persistence for region change requests (ADR-0008 Option C).</summary>
public interface IRegionChangeRequestRepository
{
    Task AddAsync(RegionChangeRequest request, CancellationToken cancellationToken);

    Task<RegionChangeRequest?> FindAsync(Guid id, CancellationToken cancellationToken);

    /// <summary>Persists changes. As with sessions and sensitive-session requests, the instance must
    /// be one this repository returned within the same unit of work.</summary>
    Task UpdateAsync(RegionChangeRequest request, CancellationToken cancellationToken);

    /// <summary>
    /// Pending requests, oldest first, up to <paramref name="limit"/>. Unlike the sensitive-session
    /// approver queue this is not paged: region changes are rare, deliberate operations (standing up
    /// or retiring an egress stamp), not something an ordinary user can flood the way a session
    /// request can, so a single bounded read is proportionate rather than under-defended.
    /// </summary>
    Task<IReadOnlyList<RegionChangeRequest>> ListPendingAsync(int limit, CancellationToken cancellationToken);

    /// <summary>Most recently resolved requests first, for a short "recently applied/dismissed" history.</summary>
    Task<IReadOnlyList<RegionChangeRequest>> ListRecentlyResolvedAsync(int limit, CancellationToken cancellationToken);
}
