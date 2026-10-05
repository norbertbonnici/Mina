using Microsoft.Extensions.Options;
using Mina.ControlPlane.Application.Telemetry;
using Mina.ControlPlane.Domain.Telemetry;
using Mina.ControlPlane.Persistence;

namespace Mina.ControlPlane.Application.Tests;

/// <summary>
/// C3 retention (LOGGING_AND_PRIVACY §7, backlog M4-9). This is the only code in the platform that
/// destroys analyst data on purpose, so the tests are as concerned with what it must *not* delete
/// as with what it must.
/// </summary>
public sealed class TelemetryRetentionServiceTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 2, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void The_shipped_configuration_has_no_retention_period()
    {
        // Guards the default itself, not the behaviour given a null. The test below passes an
        // explicit null and so would keep passing if someone gave the property an initialiser —
        // at which point an unconfigured deployment would start destroying analyst records on a
        // period no data-protection officer had approved.
        Assert.Null(new TelemetryRetentionOptions().HostnameRetentionDays);
    }

    [Fact]
    public async Task Nothing_is_deleted_when_no_retention_period_is_configured()
    {
        // The default state, and the one that matters most: the operating value is a proposal
        // awaiting ratification, so an unconfigured platform must keep everything rather than pick
        // a period of its own.
        var store = new InMemoryTelemetryRepository();
        var session = Guid.NewGuid();
        await Add(store, session, Now.AddYears(-3));

        var audit = new RecordingRetentionAudit();
        var outcome = await Service(store, audit, retentionDays: null).ApplyAsync(default);

        Assert.False(outcome.Enforced);
        Assert.Equal(0, outcome.Total);
        Assert.Single(await store.ListForSessionAsync(session, default));
        Assert.Empty(audit.Applied);
    }

    [Fact]
    public async Task Telemetry_older_than_the_period_is_deleted_and_newer_telemetry_is_kept()
    {
        var store = new InMemoryTelemetryRepository();
        var session = Guid.NewGuid();
        await Add(store, session, Now.AddDays(-181));   // expired
        await Add(store, session, Now.AddDays(-179));   // inside the window
        await Add(store, session, Now.AddHours(-1));    // today

        var outcome = await Service(store, new RecordingRetentionAudit(), retentionDays: 180).ApplyAsync(default);

        Assert.True(outcome.Enforced);
        Assert.Equal(1, outcome.Hostnames);

        // The boundary matters more than the count: a period of 180 days that deletes at 179 is a
        // different commitment from the one that was ratified.
        var remaining = await store.ListForSessionAsync(session, default);
        Assert.Equal(2, remaining.Count);
        Assert.All(remaining, o => Assert.True(o.OccurredAt > Now.AddDays(-180)));
    }

    [Fact]
    public async Task Suppressed_summaries_expire_on_the_same_clock_as_the_hostnames_they_replaced()
    {
        // A summary is what is left of a suppressed session's traffic. Keeping it longer than the
        // destinations of an unsuppressed session would mean asking for suppression bought a longer
        // retention period, which inverts the point of ADR-0003.
        var store = new InMemoryTelemetryRepository();
        var session = Guid.NewGuid();
        await store.AddSuppressedSummaryAsync(
            SuppressedTrafficSummary.Record(session, "westeurope", Now.AddDays(-181), 4, 900), default);
        await store.AddSuppressedSummaryAsync(
            SuppressedTrafficSummary.Record(session, "westeurope", Now.AddDays(-1), 2, 100), default);

        var outcome = await Service(store, new RecordingRetentionAudit(), retentionDays: 180).ApplyAsync(default);

        Assert.Equal(1, outcome.SuppressedSummaries);
        Assert.Single(await store.ListSuppressedForSessionAsync(session, default));
    }

    [Fact]
    public async Task A_backlog_larger_than_one_batch_is_drained_in_a_single_pass()
    {
        // Batching bounds the transaction, not the pass. If a pass stopped after one batch, the
        // first run after this ships — against everything accumulated since the platform started —
        // would take weeks of six-hourly passes, during which the retention period is not met.
        var store = new InMemoryTelemetryRepository();
        var session = Guid.NewGuid();
        for (var i = 0; i < 25; i++)
        {
            await Add(store, session, Now.AddDays(-200).AddMinutes(i));
        }

        var outcome = await Service(store, new RecordingRetentionAudit(), retentionDays: 180, batchSize: 10)
            .ApplyAsync(default);

        Assert.Equal(25, outcome.Hostnames);
        Assert.Empty(await store.ListForSessionAsync(session, default));
    }

    [Fact]
    public async Task Deletion_is_recorded_in_the_audit_trail()
    {
        // Without this event, "the hostnames are gone" and "the hostnames were never recorded" are
        // indistinguishable after the fact, because the evidence deleted itself.
        var store = new InMemoryTelemetryRepository();
        await Add(store, Guid.NewGuid(), Now.AddDays(-400));
        var audit = new RecordingRetentionAudit();

        await Service(store, audit, retentionDays: 180).ApplyAsync(default);

        var recorded = Assert.Single(audit.Applied);
        Assert.Equal(1, recorded.Hostnames);
        Assert.Equal(Now.AddDays(-180), recorded.Cutoff);
    }

    [Fact]
    public async Task A_pass_that_deletes_nothing_writes_no_audit_event()
    {
        // Retention runs every few hours forever. An event per pass would bury the passes that
        // actually deleted something under thousands that did not.
        var store = new InMemoryTelemetryRepository();
        await Add(store, Guid.NewGuid(), Now.AddDays(-1));
        var audit = new RecordingRetentionAudit();

        await Service(store, audit, retentionDays: 180).ApplyAsync(default);

        Assert.Empty(audit.Applied);
    }

    [Theory]
    [InlineData(0, null)]
    [InlineData(-1, null)]
    [InlineData(null, 0)]
    [InlineData(null, 20_000)]
    public void Invalid_configuration_is_rejected(int? days, int? batchSize)
    {
        var options = new TelemetryRetentionOptions();
        if (days is not null)
        {
            options.HostnameRetentionDays = days;
        }

        if (batchSize is not null)
        {
            options.BatchSize = batchSize.Value;
        }

        Assert.NotEmpty(options.Validate());
    }

    private static async Task Add(InMemoryTelemetryRepository store, Guid session, DateTimeOffset at) =>
        await store.AddHostnamesAsync(
            [HostnameObservation.Record(session, "westeurope", at, "example.test", 443, 1, 1, 200)], default);

    private static TelemetryRetentionService Service(
        InMemoryTelemetryRepository store, ITelemetryAuditSink audit, int? retentionDays, int batchSize = 500) =>
        new(store,
            audit,
            Options.Create(new TelemetryRetentionOptions
            {
                HostnameRetentionDays = retentionDays,
                BatchSize = batchSize,
            }),
            new FixedNow());

    private sealed class FixedNow : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private sealed class RecordingRetentionAudit : ITelemetryAuditSink
    {
        public List<(DateTimeOffset Cutoff, int Hostnames, int Summaries)> Applied { get; } = [];

        public Task SuppressionMismatchAsync(
            Guid sessionId, string region, int itemCount, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task UnattributableTelemetryAsync(
            Guid sessionId, string region, int itemCount, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task RegionMismatchAsync(
            Guid sessionId, string claimedRegion, string sessionRegion, int itemCount,
            CancellationToken cancellationToken) => Task.CompletedTask;

        public Task RetentionAppliedAsync(
            DateTimeOffset cutoff, int hostnames, int suppressedSummaries, CancellationToken cancellationToken)
        {
            Applied.Add((cutoff, hostnames, suppressedSummaries));
            return Task.CompletedTask;
        }

        public Task TelemetryViewedAsync(
            string viewerUpn, string viewerObjectId, string? targetAnalystUpn,
            DateTimeOffset rangeFrom, DateTimeOffset rangeTo, int sessionCount,
            CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
