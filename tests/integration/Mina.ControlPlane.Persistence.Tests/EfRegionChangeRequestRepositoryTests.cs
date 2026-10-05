using Mina.ControlPlane.Domain.Regions;
using Mina.ControlPlane.Persistence;

namespace Mina.ControlPlane.Persistence.Tests;

public sealed class EfRegionChangeRequestRepositoryTests(SqliteDatabaseFixture db) : IClassFixture<SqliteDatabaseFixture>
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 11, 9, 0, 0, TimeSpan.Zero);

    private const string RequesterOid = "oid-admin";
    private const string RequesterUpn = "admin@example.org";

    private readonly SqliteDatabaseFixture _db = db;

    private static RegionChangeRequest NewRequest(RegionChangeKind kind = RegionChangeKind.Activate, string region = "northeurope") =>
        RegionChangeRequest.Create(Guid.NewGuid(), RequesterOid, RequesterUpn, kind, region, "capacity need", T0);

    private async Task<Guid> SeedAsync(RegionChangeRequest request)
    {
        await using var context = _db.CreateContext();
        await new EfRegionChangeRequestRepository(context).AddAsync(request, default);
        return request.Id;
    }

    [Fact]
    public async Task Add_then_find_round_trips_the_request()
    {
        var request = NewRequest(RegionChangeKind.AddApproved, "francesouth");
        await SeedAsync(request);

        await using var context = _db.CreateContext();
        var loaded = await new EfRegionChangeRequestRepository(context).FindAsync(request.Id, default);

        Assert.NotNull(loaded);
        Assert.Equal("francesouth", loaded.RegionName);
        Assert.Equal(RegionChangeKind.AddApproved, loaded.Kind);
        Assert.Equal(RequesterOid, loaded.RequestedByObjectId);
        Assert.Equal(RequesterUpn, loaded.RequestedByUpn);
        Assert.Equal("capacity need", loaded.Justification);
        Assert.Equal(T0, loaded.RequestedAt);
        Assert.Equal(RegionChangeRequestStatus.Pending, loaded.Status);
    }

    [Fact]
    public async Task Applying_persists_the_full_resolution_trail()
    {
        var id = await SeedAsync(NewRequest());
        var resolvedAt = T0.AddHours(3);

        await using (var context = _db.CreateContext())
        {
            var repository = new EfRegionChangeRequestRepository(context);
            var request = await repository.FindAsync(id, default);
            request!.MarkApplied("oid-resolver", "resolver@example.org", resolvedAt, "deployed via script run #7");
            await repository.UpdateAsync(request, default);
        }

        await using var verify = _db.CreateContext();
        var reloaded = await new EfRegionChangeRequestRepository(verify).FindAsync(id, default);

        Assert.Equal(RegionChangeRequestStatus.Applied, reloaded!.Status);
        Assert.Equal("oid-resolver", reloaded.ResolvedByObjectId);
        Assert.Equal("resolver@example.org", reloaded.ResolvedByUpn);
        Assert.Equal(resolvedAt, reloaded.ResolvedAt);
        Assert.Equal("deployed via script run #7", reloaded.ResolutionNote);
    }

    [Fact]
    public async Task ListPending_excludes_resolved_requests()
    {
        // SqliteDatabaseFixture's connection is shared across every test in this class (its own
        // remarks explain why), so an unfiltered list query can see sibling tests' rows too --
        // asserting by this test's own ids rather than by exact list contents/count is what makes
        // this robust regardless of what else the fixture is currently holding.
        var pendingId = await SeedAsync(NewRequest(region: "northeurope"));
        var toResolveId = await SeedAsync(NewRequest(region: "westeurope"));

        await using (var context = _db.CreateContext())
        {
            var repository = new EfRegionChangeRequestRepository(context);
            var request = await repository.FindAsync(toResolveId, default);
            request!.Dismiss("oid-resolver", "resolver@example.org", T0.AddHours(1), "not needed");
            await repository.UpdateAsync(request, default);
        }

        await using var verify = _db.CreateContext();
        var pending = await new EfRegionChangeRequestRepository(verify).ListPendingAsync(50, default);

        Assert.Contains(pending, r => r.Id == pendingId);
        Assert.DoesNotContain(pending, r => r.Id == toResolveId);
    }

    [Fact]
    public async Task ListRecentlyResolved_excludes_pending_requests_and_orders_newest_first()
    {
        var stillPendingId = await SeedAsync(NewRequest(region: "northeurope"));
        var firstResolvedId = await SeedAsync(NewRequest(region: "westeurope"));
        var secondResolvedId = await SeedAsync(NewRequest(region: "spaincentral"));

        await using (var context = _db.CreateContext())
        {
            var repository = new EfRegionChangeRequestRepository(context);
            var first = await repository.FindAsync(firstResolvedId, default);
            first!.Dismiss("oid-resolver", "resolver@example.org", T0.AddHours(1), "reason a");
            await repository.UpdateAsync(first, default);

            var second = await repository.FindAsync(secondResolvedId, default);
            second!.MarkApplied("oid-resolver", "resolver@example.org", T0.AddHours(2), "reason b");
            await repository.UpdateAsync(second, default);
        }

        await using var verify = _db.CreateContext();
        var resolved = await new EfRegionChangeRequestRepository(verify).ListRecentlyResolvedAsync(50, default);

        Assert.DoesNotContain(resolved, r => r.Id == stillPendingId);
        // Newest first: secondResolvedId's ResolvedAt is later than firstResolvedId's, so it must
        // appear at an earlier index -- checked by relative position, not absolute, since sibling
        // tests sharing this fixture may have their own resolved rows interspersed.
        var secondIndex = resolved.ToList().FindIndex(r => r.Id == secondResolvedId);
        var firstIndex = resolved.ToList().FindIndex(r => r.Id == firstResolvedId);
        Assert.True(secondIndex >= 0 && firstIndex >= 0, "Both resolved requests should be present.");
        Assert.True(secondIndex < firstIndex, "The more recently resolved request should be listed first.");
    }
}
