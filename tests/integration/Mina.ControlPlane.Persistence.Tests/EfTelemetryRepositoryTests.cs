using Mina.ControlPlane.Domain.Telemetry;
using Mina.ControlPlane.Persistence;

namespace Mina.ControlPlane.Persistence.Tests;

public sealed class EfTelemetryRepositoryTests(SqliteDatabaseFixture db) : IClassFixture<SqliteDatabaseFixture>
{
    private static readonly DateTimeOffset T0 = new(2026, 8, 31, 9, 0, 0, TimeSpan.Zero);
    private const string Region = "westeurope";

    private readonly SqliteDatabaseFixture _db = db;

    [Fact]
    public async Task Hostname_observations_round_trip()
    {
        var sessionId = Guid.NewGuid();
        await using (var context = _db.CreateContext())
        {
            await new EfTelemetryRepository(context).AddHostnamesAsync(
            [
                HostnameObservation.Record(sessionId, Region, T0, "example.org", 443, 100, 900, 42),
                HostnameObservation.Record(sessionId, Region, T0.AddMinutes(1), "www.iana.org", 443, 10, 20, 7),
            ], default);
        }

        await using var verify = _db.CreateContext();
        var stored = await new EfTelemetryRepository(verify).ListForSessionAsync(sessionId, default);

        Assert.Equal(2, stored.Count);
        // Newest first.
        Assert.Equal("www.iana.org", stored[0].Hostname);
        Assert.Equal("example.org", stored[1].Hostname);
        Assert.Equal(900, stored[1].BytesDown);
        Assert.Equal(Region, stored[1].Region);
        Assert.Equal(T0, stored[1].OccurredAt);
    }

    [Fact]
    public async Task Suppressed_summaries_round_trip_and_carry_no_destination()
    {
        var sessionId = Guid.NewGuid();
        await using (var context = _db.CreateContext())
        {
            await new EfTelemetryRepository(context).AddSuppressedSummaryAsync(
                SuppressedTrafficSummary.Record(sessionId, Region, T0, connectionCount: 12, bytesTotal: 4096), default);
        }

        await using var verify = _db.CreateContext();
        var summary = Assert.Single(
            await new EfTelemetryRepository(verify).ListSuppressedForSessionAsync(sessionId, default));

        Assert.Equal(12, summary.ConnectionCount);
        Assert.Equal(4096, summary.BytesTotal);
        Assert.Equal(T0, summary.IntervalStart);
        // A suppressed session leaves counts behind, and nothing else — the type has no hostname.
        Assert.Empty(await new EfTelemetryRepository(verify).ListForSessionAsync(sessionId, default));
    }

    [Fact]
    public async Task Telemetry_is_isolated_per_session()
    {
        var first = Guid.NewGuid();
        var second = Guid.NewGuid();

        await using (var context = _db.CreateContext())
        {
            var repository = new EfTelemetryRepository(context);
            await repository.AddHostnamesAsync(
                [HostnameObservation.Record(first, Region, T0, "first.example", 443, 1, 1, 1)], default);
            await repository.AddHostnamesAsync(
                [HostnameObservation.Record(second, Region, T0, "second.example", 443, 1, 1, 1)], default);
        }

        await using var verify = _db.CreateContext();
        var repo = new EfTelemetryRepository(verify);

        Assert.Equal("first.example", Assert.Single(await repo.ListForSessionAsync(first, default)).Hostname);
        Assert.Equal("second.example", Assert.Single(await repo.ListForSessionAsync(second, default)).Hostname);
    }

    [Fact]
    public async Task Adding_an_empty_batch_does_nothing()
    {
        await using var context = _db.CreateContext();

        await new EfTelemetryRepository(context).AddHostnamesAsync([], default);

        Assert.Empty(await new EfTelemetryRepository(context).ListForSessionAsync(Guid.NewGuid(), default));
    }
}
