using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Mina.ControlPlane.Domain.Audit;
using Mina.ControlPlane.Domain.Telemetry;

namespace Mina.ControlPlane.Persistence.Tests;

/// <summary>
/// C3 retention against a real database (M4-9). The unit tests exercise the rules on the in-memory
/// store; these exercise the thing the in-memory store cannot fail at — whether the bounded
/// <c>ExecuteDelete</c> translates to SQL at all. A retention sweep that throws at runtime, in a
/// background service whose failures are logged and swallowed, would look exactly like a platform
/// that is enforcing retention.
/// </summary>
public sealed class TelemetryRetentionPersistenceTests : IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 9, 2, 12, 0, 0, TimeSpan.Zero);

    private readonly SqliteConnection _connection;

    public TelemetryRetentionPersistenceTests()
    {
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();
        using var context = CreateContext();
        context.Database.EnsureCreated();
    }

    public void Dispose() => _connection.Dispose();

    private MinaDbContext CreateContext() =>
        new(new DbContextOptionsBuilder<MinaDbContext>().UseSqlite(_connection).Options);

    [Fact]
    public async Task Expired_hostnames_are_deleted_and_current_ones_survive()
    {
        var session = Guid.NewGuid();
        await Seed(session, Now.AddDays(-200), Now.AddDays(-181), Now.AddDays(-179), Now.AddHours(-2));

        var deleted = await new EfTelemetryRepository(CreateContext())
            .DeleteHostnamesBeforeAsync(Now.AddDays(-180), 500, default);

        Assert.Equal(2, deleted);
        var remaining = await new EfTelemetryRepository(CreateContext()).ListForSessionAsync(session, default);
        Assert.Equal(2, remaining.Count);
    }

    [Fact]
    public async Task The_batch_limit_is_honoured_and_takes_the_oldest_first()
    {
        // Bounding the pass is only useful if a bounded pass makes progress on the oldest data.
        // Deleting an arbitrary expired slice would leave the oldest rows behind indefinitely.
        var session = Guid.NewGuid();
        await Seed(session, Now.AddDays(-400), Now.AddDays(-300), Now.AddDays(-200));

        var repository = new EfTelemetryRepository(CreateContext());
        var deleted = await repository.DeleteHostnamesBeforeAsync(Now.AddDays(-180), 2, default);

        Assert.Equal(2, deleted);
        var remaining = await new EfTelemetryRepository(CreateContext()).ListForSessionAsync(session, default);
        var survivor = Assert.Single(remaining);
        Assert.Equal(Now.AddDays(-200), survivor.OccurredAt);
    }

    [Fact]
    public async Task Suppressed_summaries_delete_on_their_own_timestamp()
    {
        var session = Guid.NewGuid();
        var repository = new EfTelemetryRepository(CreateContext());
        await repository.AddSuppressedSummaryAsync(
            SuppressedTrafficSummary.Record(session, "westeurope", Now.AddDays(-200), 3, 500), default);
        await repository.AddSuppressedSummaryAsync(
            SuppressedTrafficSummary.Record(session, "westeurope", Now.AddDays(-10), 3, 500), default);

        var deleted = await new EfTelemetryRepository(CreateContext())
            .DeleteSuppressedSummariesBeforeAsync(Now.AddDays(-180), 500, default);

        Assert.Equal(1, deleted);
        Assert.Single(await new EfTelemetryRepository(CreateContext())
            .ListSuppressedForSessionAsync(session, default));
    }

    [Fact]
    public async Task Retention_touches_no_other_table()
    {
        // Hostname telemetry and the governance audit trail are different data classes with
        // different retention, and the audit chain is hash-linked: a cascade from this delete into
        // audit or session rows would break verification while looking like successful housekeeping.
        var session = Guid.NewGuid();
        await Seed(session, Now.AddDays(-400));

        await using (var context = CreateContext())
        {
            context.Add(AuditEvent.Append(
                sequence: 1,
                previousHash: AuditEvent.GenesisHash,
                eventType: "session_started",
                severity: AuditSeverity.Info,
                component: AuditComponent.ControlPlane,
                occurredAt: Now.AddDays(-400),
                environment: "test",
                sessionId: session));
            await context.SaveChangesAsync();
        }

        await new EfTelemetryRepository(CreateContext())
            .DeleteHostnamesBeforeAsync(Now.AddDays(-180), 500, default);

        await using var check = CreateContext();
        Assert.Equal(1, await check.Set<AuditEvent>().CountAsync());
    }

    private async Task Seed(Guid session, params DateTimeOffset[] times)
    {
        var repository = new EfTelemetryRepository(CreateContext());
        foreach (var at in times)
        {
            await repository.AddHostnamesAsync(
                [HostnameObservation.Record(session, "westeurope", at, "example.test", 443, 10, 20, 5)], default);
        }
    }
}
