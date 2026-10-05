using Microsoft.EntityFrameworkCore;
using Mina.ControlPlane.Domain.Sessions;
using Mina.ControlPlane.Persistence;

namespace Mina.ControlPlane.Persistence.Tests;

public sealed class EfSessionRepositoryTests(SqliteDatabaseFixture db) : IClassFixture<SqliteDatabaseFixture>
{
    private static readonly DateTimeOffset T0 = new(2026, 8, 31, 9, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan Lease = TimeSpan.FromMinutes(60);

    private readonly SqliteDatabaseFixture _db = db;

    private static ResearchSession NewSession(Guid? id = null, string oid = "oid-1") => ResearchSession.Issue(
        id ?? Guid.NewGuid(), oid, "analyst@example.org", "device-1", "westeurope", T0, Lease, "SERIAL-1");

    private async Task<Guid> SeedAsync(ResearchSession? session = null)
    {
        session ??= NewSession();
        await using var context = _db.CreateContext();
        await new EfSessionRepository(context).AddAsync(session, default);
        return session.Id;
    }

    [Fact]
    public async Task Add_then_find_round_trips_every_field()
    {
        var session = NewSession();
        await SeedAsync(session);

        await using var context = _db.CreateContext();
        var loaded = await new EfSessionRepository(context).FindAsync(session.Id, default);

        Assert.NotNull(loaded);
        Assert.Equal(session.Id, loaded.Id);
        Assert.Equal("oid-1", loaded.UserObjectId);
        Assert.Equal("analyst@example.org", loaded.UserPrincipalName);
        Assert.Equal("device-1", loaded.DeviceId);
        Assert.Equal("westeurope", loaded.Region);
        Assert.Equal("SERIAL-1", loaded.CertificateSerialNumber);
        Assert.Equal(SessionState.Active, loaded.State);
        Assert.Equal(SessionMode.Normal, loaded.Mode);
        Assert.Equal(T0, loaded.CreatedAt);
        Assert.Equal(T0 + Lease, loaded.LeaseExpiresAt);
        Assert.Null(loaded.EndedAt);
        Assert.Null(loaded.EndReason);
        Assert.Null(loaded.RevokedBy);
    }

    [Fact]
    public async Task Find_returns_null_for_an_unknown_session()
    {
        await using var context = _db.CreateContext();

        Assert.Null(await new EfSessionRepository(context).FindAsync(Guid.NewGuid(), default));
    }

    [Fact]
    public async Task Renewal_is_persisted()
    {
        var id = await SeedAsync();

        await using (var context = _db.CreateContext())
        {
            var repository = new EfSessionRepository(context);
            var session = await repository.FindAsync(id, default);
            session!.Renew(T0.AddMinutes(50), Lease, "SERIAL-2");
            await repository.UpdateAsync(session, default);
        }

        await using var verify = _db.CreateContext();
        var reloaded = await new EfSessionRepository(verify).FindAsync(id, default);
        Assert.Equal("SERIAL-2", reloaded!.CertificateSerialNumber);
        Assert.Equal(T0.AddMinutes(50) + Lease, reloaded.LeaseExpiresAt);
        Assert.Equal(SessionState.Active, reloaded.State);
    }

    [Fact]
    public async Task Revocation_is_persisted_with_the_actor()
    {
        var id = await SeedAsync();

        await using (var context = _db.CreateContext())
        {
            var repository = new EfSessionRepository(context);
            var session = await repository.FindAsync(id, default);
            session!.Revoke(T0.AddMinutes(5), "admin@example.org");
            await repository.UpdateAsync(session, default);
        }

        await using var verify = _db.CreateContext();
        var reloaded = await new EfSessionRepository(verify).FindAsync(id, default);
        Assert.Equal(SessionState.Revoked, reloaded!.State);
        Assert.Equal("admin@example.org", reloaded.RevokedBy);
        Assert.False(reloaded.IsUsableAt(T0.AddMinutes(6)));
    }

    [Fact]
    public async Task End_reason_and_timestamp_are_persisted()
    {
        var id = await SeedAsync();

        await using (var context = _db.CreateContext())
        {
            var repository = new EfSessionRepository(context);
            var session = await repository.FindAsync(id, default);
            session!.End(T0.AddMinutes(20), SessionEndReason.TunnelLost);
            await repository.UpdateAsync(session, default);
        }

        await using var verify = _db.CreateContext();
        var reloaded = await new EfSessionRepository(verify).FindAsync(id, default);
        Assert.Equal(SessionState.Ended, reloaded!.State);
        Assert.Equal(SessionEndReason.TunnelLost, reloaded.EndReason);
        Assert.Equal(T0.AddMinutes(20), reloaded.EndedAt);
    }

    [Fact]
    public async Task Enums_are_stored_as_readable_strings()
    {
        // Filter on the serial rather than the id: it is a plain string column, so the assertion
        // does not depend on how the provider represents a Guid on disk.
        const string serial = "SERIAL-ENUM-CHECK";
        await SeedAsync(ResearchSession.Issue(
            Guid.NewGuid(), "oid-enum", "analyst@example.org", "device-1", "westeurope", T0, Lease, serial));

        await using var context = _db.CreateContext();
        var connection = context.Database.GetDbConnection();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT State, Mode FROM Sessions WHERE CertificateSerialNumber = $serial";
        var parameter = command.CreateParameter();
        parameter.ParameterName = "$serial";
        parameter.Value = serial;
        command.Parameters.Add(parameter);

        await using var reader = await command.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        Assert.Equal("Active", reader.GetString(0));
        Assert.Equal("Normal", reader.GetString(1));
    }

    [Fact]
    public async Task A_stale_write_is_rejected_rather_than_overwriting_a_revocation()
    {
        // An administrator revokes while the analyst's agent renews, each in its own unit of work.
        var id = await SeedAsync();

        await using var analystContext = _db.CreateContext();
        await using var adminContext = _db.CreateContext();

        var analystRepository = new EfSessionRepository(analystContext);
        var adminRepository = new EfSessionRepository(adminContext);

        var analystView = await analystRepository.FindAsync(id, default);
        var adminView = await adminRepository.FindAsync(id, default);

        adminView!.Revoke(T0.AddMinutes(5), "admin@example.org");
        await adminRepository.UpdateAsync(adminView, default);

        analystView!.Renew(T0.AddMinutes(5), Lease, "SERIAL-2");
        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(
            () => analystRepository.UpdateAsync(analystView, default));

        // The revocation stands: the stale renewal did not resurrect the session.
        await using var verify = _db.CreateContext();
        var reloaded = await new EfSessionRepository(verify).FindAsync(id, default);
        Assert.Equal(SessionState.Revoked, reloaded!.State);
        Assert.Equal("SERIAL-1", reloaded.CertificateSerialNumber);
    }

    [Fact]
    public async Task Updating_a_detached_session_is_refused()
    {
        var detached = NewSession();
        await SeedAsync(detached);

        await using var context = _db.CreateContext();
        detached.End(T0.AddMinutes(1), SessionEndReason.EndedByUser);

        // This instance was never loaded by *this* context, so its concurrency token is unknown;
        // saving it would silently discard a concurrent change.
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => new EfSessionRepository(context).UpdateAsync(detached, default));
    }

    [Fact]
    public async Task Sessions_are_isolated_by_id()
    {
        var first = await SeedAsync(NewSession(oid: "oid-1"));
        var second = await SeedAsync(NewSession(oid: "oid-2"));

        await using var context = _db.CreateContext();
        var repository = new EfSessionRepository(context);

        Assert.Equal("oid-1", (await repository.FindAsync(first, default))!.UserObjectId);
        Assert.Equal("oid-2", (await repository.FindAsync(second, default))!.UserObjectId);
    }

    [Fact]
    public async Task ListDistinctAnalysts_collapses_repeat_sessions_and_orders_by_most_recent()
    {
        // Found live 2026-09-07 against the real SQL Server deployment (InvalidOperationException,
        // browsing-data page): the production query built AnalystSummary directly inside a
        // post-GroupBy Select, which no EF Core provider can translate. Confirmed, not assumed,
        // that this is not a SQL-Server-specific gap: stashing just the production fix and running
        // this exact test against SQLite reproduces the identical exception -- ListDistinctAnalystsAsync
        // simply had no test against any real EF Core provider before this one, only against
        // InMemorySessionRepository's hand-written LINQ-to-objects implementation, which cannot hit
        // a translation failure by construction.
        await SeedAsync(NewSession(Guid.NewGuid(), "oid-a"));
        var secondForA = ResearchSession.Issue(
            Guid.NewGuid(), "oid-a", "analyst@example.org", "device-1", "westeurope",
            T0.AddHours(2), Lease, "SERIAL-A2");
        await SeedAsync(secondForA);
        await SeedAsync(ResearchSession.Issue(
            Guid.NewGuid(), "oid-b", "other@example.org", "device-1", "westeurope",
            T0.AddHours(1), Lease, "SERIAL-B1"));

        await using var context = _db.CreateContext();
        var result = await new EfSessionRepository(context).ListDistinctAnalystsAsync(default);

        Assert.Equal(2, result.Count);
        // Most recent first: oid-a's later session (T0+2h) outranks oid-b's only session (T0+1h).
        Assert.Equal("oid-a", result[0].UserObjectId);
        Assert.Equal(T0.AddHours(2), result[0].LastSessionCreatedAt);
        Assert.Equal("oid-b", result[1].UserObjectId);
        Assert.Equal(T0.AddHours(1), result[1].LastSessionCreatedAt);
    }
}
