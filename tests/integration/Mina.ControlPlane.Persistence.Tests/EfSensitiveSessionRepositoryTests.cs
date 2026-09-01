using Microsoft.EntityFrameworkCore;
using Mina.ControlPlane.Domain.SensitiveSessions;
using Mina.ControlPlane.Persistence;

namespace Mina.ControlPlane.Persistence.Tests;

public sealed class EfSensitiveSessionRepositoryTests(SqliteDatabaseFixture db) : IClassFixture<SqliteDatabaseFixture>
{
    private static readonly DateTimeOffset T0 = new(2026, 8, 31, 9, 0, 0, TimeSpan.Zero);
    private static readonly SensitiveSessionPolicy Policy = new(TimeSpan.FromHours(4));

    private const string AnalystOid = "oid-analyst";
    private const string ApproverOid = "oid-manager";

    private readonly SqliteDatabaseFixture _db = db;

    private static SensitiveSessionRequest NewRequest(Guid? sessionId = null, string reference = "CASE-1") =>
        SensitiveSessionRequest.Create(
            Guid.NewGuid(), sessionId ?? Guid.NewGuid(), AnalystOid, "analyst@fiaumalta.org",
            reference, TimeSpan.FromHours(2), Policy, T0);

    private async Task<Guid> SeedAsync(SensitiveSessionRequest request)
    {
        await using var context = _db.CreateContext();
        await new EfSensitiveSessionRepository(context).AddAsync(request, default);
        return request.Id;
    }

    [Fact]
    public async Task Add_then_find_round_trips_the_approval_record()
    {
        var sessionId = Guid.NewGuid();
        var request = NewRequest(sessionId, "CASE-ROUNDTRIP");
        await SeedAsync(request);

        await using var context = _db.CreateContext();
        var loaded = await new EfSensitiveSessionRepository(context).FindAsync(request.Id, default);

        Assert.NotNull(loaded);
        Assert.Equal(sessionId, loaded.SessionId);
        Assert.Equal(AnalystOid, loaded.RequesterObjectId);
        Assert.Equal("analyst@fiaumalta.org", loaded.RequesterUpn);
        Assert.Equal("CASE-ROUNDTRIP", loaded.JustificationReference);
        Assert.Equal(TimeSpan.FromHours(2), loaded.RequestedDuration);
        Assert.Equal(SensitiveSessionState.Requested, loaded.State);
        Assert.Equal(T0, loaded.RequestedAt);
    }

    [Fact]
    public async Task Approval_and_activation_are_persisted_with_the_full_decision_trail()
    {
        var id = await SeedAsync(NewRequest());

        await using (var context = _db.CreateContext())
        {
            var repository = new EfSensitiveSessionRepository(context);
            var request = await repository.FindAsync(id, default);
            request!.Approve(ApproverOid, "manager@fiaumalta.org", TimeSpan.FromHours(1), Policy, T0);
            request.Activate(T0.AddMinutes(5));
            await repository.UpdateAsync(request, default);
        }

        await using var verify = _db.CreateContext();
        var reloaded = await new EfSensitiveSessionRepository(verify).FindAsync(id, default);

        // The mandatory retained metadata of ADR-0003 survives a round trip.
        Assert.Equal(SensitiveSessionState.ActiveSuppressed, reloaded!.State);
        Assert.Equal(ApproverOid, reloaded.ApproverObjectId);
        Assert.Equal("manager@fiaumalta.org", reloaded.ApproverUpn);
        Assert.Equal(T0, reloaded.ApprovedAt);
        Assert.Equal(T0.AddHours(1), reloaded.ExpiresAt);
        Assert.Equal(T0.AddMinutes(5), reloaded.ActivatedAt);
        Assert.True(reloaded.IsSuppressing);
    }

    [Fact]
    public async Task Pending_lists_only_undecided_requests_oldest_first()
    {
        var older = SensitiveSessionRequest.Create(
            Guid.NewGuid(), Guid.NewGuid(), AnalystOid, "analyst@fiaumalta.org", "CASE-OLD",
            TimeSpan.FromHours(1), Policy, T0.AddMinutes(-30));
        var newer = NewRequest(reference: "CASE-NEW");
        var decided = NewRequest(reference: "CASE-DECIDED");

        await SeedAsync(older);
        await SeedAsync(newer);
        await SeedAsync(decided);

        await using (var context = _db.CreateContext())
        {
            var repository = new EfSensitiveSessionRepository(context);
            var toDeny = await repository.FindAsync(decided.Id, default);
            toDeny!.Deny(ApproverOid, "manager@fiaumalta.org", T0);
            await repository.UpdateAsync(toDeny, default);
        }

        await using var verify = _db.CreateContext();
        var pending = await new EfSensitiveSessionRepository(verify).ListPendingAsync(100, default);

        var references = pending.Requests.Select(r => r.JustificationReference).ToList();
        Assert.DoesNotContain("CASE-DECIDED", references);
        Assert.True(references.IndexOf("CASE-OLD") < references.IndexOf("CASE-NEW"));
    }

    [Fact]
    public async Task Expired_lists_open_approvals_past_their_window_only()
    {
        var elapsed = NewRequest(reference: "CASE-ELAPSED");
        var current = NewRequest(reference: "CASE-CURRENT");
        var untouched = NewRequest(reference: "CASE-PENDING");
        await SeedAsync(elapsed);
        await SeedAsync(current);
        await SeedAsync(untouched);

        await using (var context = _db.CreateContext())
        {
            var repository = new EfSensitiveSessionRepository(context);
            var a = await repository.FindAsync(elapsed.Id, default);
            a!.Approve(ApproverOid, "manager@fiaumalta.org", TimeSpan.FromMinutes(30), Policy, T0);
            await repository.UpdateAsync(a, default);

            var b = await repository.FindAsync(current.Id, default);
            b!.Approve(ApproverOid, "manager@fiaumalta.org", TimeSpan.FromHours(4), Policy, T0);
            await repository.UpdateAsync(b, default);
        }

        await using var verify = _db.CreateContext();
        var due = await new EfSensitiveSessionRepository(verify).ListExpiredAsync(T0.AddHours(1), 100, default);

        var references = due.Select(r => r.JustificationReference).ToList();
        Assert.Contains("CASE-ELAPSED", references);      // window closed
        Assert.DoesNotContain("CASE-CURRENT", references); // still inside its window
        Assert.DoesNotContain("CASE-PENDING", references); // never approved, so nothing to expire
    }

    [Fact]
    public async Task A_stale_write_cannot_overwrite_a_decision_made_concurrently()
    {
        // Two approvers open the same pending request; one denies, the other approves.
        var id = await SeedAsync(NewRequest());

        await using var firstContext = _db.CreateContext();
        await using var secondContext = _db.CreateContext();
        var first = new EfSensitiveSessionRepository(firstContext);
        var second = new EfSensitiveSessionRepository(secondContext);

        var firstView = await first.FindAsync(id, default);
        var secondView = await second.FindAsync(id, default);

        secondView!.Deny(ApproverOid, "manager@fiaumalta.org", T0);
        await second.UpdateAsync(secondView, default);

        firstView!.Approve("oid-other-manager", "other@fiaumalta.org", TimeSpan.FromHours(1), Policy, T0);
        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() => first.UpdateAsync(firstView, default));

        await using var verify = _db.CreateContext();
        var reloaded = await new EfSensitiveSessionRepository(verify).FindAsync(id, default);
        Assert.Equal(SensitiveSessionState.Denied, reloaded!.State);
    }

    [Fact]
    public async Task Requests_can_be_listed_for_a_session()
    {
        var sessionId = Guid.NewGuid();
        await SeedAsync(NewRequest(sessionId, "CASE-S1"));
        await SeedAsync(NewRequest(sessionId, "CASE-S2"));
        await SeedAsync(NewRequest(Guid.NewGuid(), "CASE-OTHER"));

        await using var context = _db.CreateContext();
        var forSession = await new EfSensitiveSessionRepository(context).ListForSessionAsync(sessionId, default);

        Assert.Equal(2, forSession.Count);
        Assert.DoesNotContain("CASE-OTHER", forSession.Select(r => r.JustificationReference));
    }

    [Fact]
    public async Task A_queue_longer_than_the_page_is_reported_as_truncated()
    {
        // Its own database, not the class fixture. This test asserts on *which* rows come back and
        // in what order, and the class fixture is one SQLite database shared by every test in the
        // class with nothing truncating between them — so against the shared fixture it was really
        // asserting on the three oldest pending rows in the whole table, which other tests also
        // write. It passed, but only by accident of ordering.
        using var db = new SqliteDatabaseFixture();
        await using (var context = db.CreateContext())
        {
            var repository = new EfSensitiveSessionRepository(context);
            for (var i = 0; i < 5; i++)
            {
                await repository.AddAsync(
                    SensitiveSessionRequest.Create(
                        Guid.NewGuid(), Guid.NewGuid(), AnalystOid, "analyst@fiaumalta.org",
                        $"CASE-PAGE-{i}", TimeSpan.FromHours(1), Policy, T0.AddMinutes(i)),
                    default);
            }
        }

        await using var verify = db.CreateContext();
        var repo = new EfSensitiveSessionRepository(verify);

        var page = await repo.ListPendingAsync(3, default);
        Assert.Equal(3, page.Requests.Count);
        Assert.True(page.HasMore);

        // Oldest first, so a flood of new requests cannot push an older one out of the page.
        Assert.Equal(
            ["CASE-PAGE-0", "CASE-PAGE-1", "CASE-PAGE-2"],
            page.Requests.Select(r => r.JustificationReference));

        var whole = await repo.ListPendingAsync(50, default);
        Assert.False(whole.HasMore);
        Assert.Equal(await repo.CountPendingAsync(default), whole.Requests.Count);
    }
}
