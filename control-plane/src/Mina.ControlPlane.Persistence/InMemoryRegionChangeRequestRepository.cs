using System.Collections.Concurrent;
using Mina.ControlPlane.Domain.Regions;

namespace Mina.ControlPlane.Persistence;

/// <summary>In-memory store for region change requests, for local development. Not durable and not
/// shared between instances — the EF repository is used whenever a connection string is configured.</summary>
public sealed class InMemoryRegionChangeRequestRepository : IRegionChangeRequestRepository
{
    private readonly ConcurrentDictionary<Guid, RegionChangeRequest> _requests = new();

    public Task AddAsync(RegionChangeRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        _requests[request.Id] = request;
        return Task.CompletedTask;
    }

    public Task<RegionChangeRequest?> FindAsync(Guid id, CancellationToken cancellationToken) =>
        Task.FromResult(_requests.GetValueOrDefault(id));

    public Task UpdateAsync(RegionChangeRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        _requests[request.Id] = request;
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<RegionChangeRequest>> ListPendingAsync(int limit, CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(limit, 1);
        return Task.FromResult<IReadOnlyList<RegionChangeRequest>>(
            [.. _requests.Values
                .Where(r => r.Status == RegionChangeRequestStatus.Pending)
                .OrderBy(r => r.RequestedAt)
                .Take(limit)]);
    }

    public Task<IReadOnlyList<RegionChangeRequest>> ListRecentlyResolvedAsync(int limit, CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(limit, 1);
        return Task.FromResult<IReadOnlyList<RegionChangeRequest>>(
            [.. _requests.Values
                .Where(r => r.Status != RegionChangeRequestStatus.Pending)
                .OrderByDescending(r => r.ResolvedAt)
                .Take(limit)]);
    }
}
