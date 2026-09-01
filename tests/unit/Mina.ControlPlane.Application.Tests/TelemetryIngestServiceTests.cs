using System.Collections.Concurrent;
using Mina.ControlPlane.Application.Telemetry;
using Mina.ControlPlane.Domain.Sessions;
using Mina.ControlPlane.Domain.Telemetry;

namespace Mina.ControlPlane.Application.Tests;

/// <summary>
/// Ingest is the point where suppression is enforced rather than trusted. These cover the case that
/// matters most: a node that keeps sending destinations for a suppressed session must not be able
/// to get them recorded, however it behaves (AC-012, threat N5).
/// </summary>
public class TelemetryIngestServiceTests
{
    private static readonly DateTimeOffset T0 = new(2026, 8, 31, 9, 0, 0, TimeSpan.Zero);
    private const string Region = "westeurope";

    [Fact]
    public async Task Hostnames_for_a_normal_session_are_recorded_and_correlated()
    {
        var h = new Harness();

        var result = await h.Service.IngestAsync(Batch(
            Item(h.SessionId, "example.org"),
            Item(h.SessionId, "www.iana.org")), default);

        Assert.Equal(2, result.Recorded);
        Assert.Equal(0, result.SuppressionMismatches);

        var stored = await h.Telemetry.ListForSessionAsync(h.SessionId, default);
        Assert.Equal(["example.org", "www.iana.org"], stored.Select(o => o.Hostname).Order());
        // AC-009: every record is attributable to the session, and through it to user and device.
        Assert.All(stored, o => Assert.Equal(h.SessionId, o.SessionId));
        Assert.All(stored, o => Assert.Equal(Region, o.Region));
    }

    [Fact]
    public async Task A_suppressed_session_never_gets_a_hostname_stored()
    {
        var h = new Harness();
        h.Session.MarkSensitive();

        var result = await h.Service.IngestAsync(Batch(
            Item(h.SessionId, "sensitive-target.example"),
            Item(h.SessionId, "another-target.example")), default);

        Assert.Equal(0, result.Recorded);
        Assert.Empty(await h.Telemetry.ListForSessionAsync(h.SessionId, default));

        // The traffic still leaves a trace — how much, not where.
        var summaries = await h.Telemetry.ListSuppressedForSessionAsync(h.SessionId, default);
        var summary = Assert.Single(summaries);
        Assert.Equal(2, summary.ConnectionCount);
        Assert.Equal(2, result.Aggregated);
    }

    [Fact]
    public async Task A_node_still_sending_destinations_for_a_suppressed_session_raises_a_mismatch()
    {
        var h = new Harness();
        h.Session.MarkSensitive();

        var result = await h.Service.IngestAsync(Batch(
            Item(h.SessionId, "should-not-be-here.example")), default);

        Assert.Equal(1, result.SuppressionMismatches);
        Assert.Equal((h.SessionId, Region, 1), Assert.Single(h.Audit.Mismatches));
        Assert.Empty(await h.Telemetry.ListForSessionAsync(h.SessionId, default));
    }

    [Fact]
    public async Task A_node_correctly_withholding_destinations_raises_no_mismatch()
    {
        var h = new Harness();
        h.Session.MarkSensitive();

        // The node obeyed the allowlist: counts, no hostname.
        var result = await h.Service.IngestAsync(Batch(
            Item(h.SessionId, hostname: null),
            Item(h.SessionId, hostname: null)), default);

        Assert.Equal(0, result.SuppressionMismatches);
        Assert.Equal(2, result.Aggregated);
        Assert.Empty(h.Audit.Mismatches);
    }

    [Fact]
    public async Task Suppression_is_decided_by_the_control_plane_not_the_batch()
    {
        // The node believes the session is normal and sends hostnames; the control plane knows it
        // is suppressed. The control plane's view wins.
        var h = new Harness();
        h.Session.MarkSensitive();

        await h.Service.IngestAsync(Batch(Item(h.SessionId, "target.example")), default);

        Assert.Empty(await h.Telemetry.ListForSessionAsync(h.SessionId, default));
    }

    [Fact]
    public async Task Telemetry_for_an_unknown_session_is_discarded_and_reported()
    {
        var h = new Harness();
        var stranger = Guid.NewGuid();

        var result = await h.Service.IngestAsync(Batch(Item(stranger, "orphan.example")), default);

        Assert.Equal(1, result.Unattributable);
        Assert.Equal(0, result.Recorded);
        Assert.Equal((stranger, Region, 1), Assert.Single(h.Audit.Unattributable));
        Assert.Empty(await h.Telemetry.ListForSessionAsync(stranger, default));
    }

    [Fact]
    public async Task A_mixed_batch_is_handled_per_session()
    {
        var h = new Harness();
        var second = ResearchSession.Issue(
            Guid.NewGuid(), "oid-2", "other@fiaumalta.org", "device-2", Region, T0,
            TimeSpan.FromHours(1), "SERIAL-2");
        second.MarkSensitive();
        await h.Sessions.AddAsync(second, default);

        var result = await h.Service.IngestAsync(Batch(
            Item(h.SessionId, "normal.example"),
            Item(second.Id, "suppressed.example"),
            Item(Guid.NewGuid(), "unknown.example")), default);

        Assert.Equal(1, result.Recorded);
        Assert.Equal(1, result.Aggregated);
        Assert.Equal(1, result.Unattributable);
        Assert.Equal(1, result.SuppressionMismatches);

        Assert.Single(await h.Telemetry.ListForSessionAsync(h.SessionId, default));
        Assert.Empty(await h.Telemetry.ListForSessionAsync(second.Id, default));
    }

    [Fact]
    public async Task Telemetry_claiming_a_session_from_another_region_is_discarded_and_reported()
    {
        var h = new Harness();

        // A node in another region submitting against this session: without the check, the region
        // is merely a label the caller picks, and one node could write browsing history against
        // another region's analysts.
        var result = await h.Service.IngestAsync(
            new TelemetryBatch("northeurope", [Item(h.SessionId, "elsewhere.example")]), default);

        Assert.Equal(0, result.Recorded);
        Assert.Equal(1, result.Unattributable);
        Assert.Equal((h.SessionId, "northeurope", Region, 1), Assert.Single(h.Audit.RegionMismatches));
        Assert.Empty(await h.Telemetry.ListForSessionAsync(h.SessionId, default));
    }

    [Fact]
    public async Task An_empty_batch_is_accepted_without_effect()
    {
        var h = new Harness();

        var result = await h.Service.IngestAsync(new TelemetryBatch(Region, []), default);

        Assert.Equal(new TelemetryIngestResult(0, 0, 0, 0), result);
    }

    [Fact]
    public async Task A_batch_without_a_region_is_rejected()
    {
        var h = new Harness();

        await Assert.ThrowsAsync<ArgumentException>(
            () => h.Service.IngestAsync(new TelemetryBatch("", [Item(h.SessionId, "x.example")]), default));
    }

    private static TelemetryBatch Batch(params TelemetryItem[] items) => new(Region, items);

    private static TelemetryItem Item(Guid sessionId, string? hostname) =>
        new(sessionId, T0, hostname, 443, BytesUp: 100, BytesDown: 900, DurationMs: 50);

    private sealed class Harness
    {
        public Harness()
        {
            Session = ResearchSession.Issue(
                SessionId, "oid-1", "analyst@fiaumalta.org", "device-1", Region, T0,
                TimeSpan.FromHours(1), "SERIAL-1");
            Sessions.AddAsync(Session, default).GetAwaiter().GetResult();
            Service = new TelemetryIngestService(Telemetry, Sessions, Audit);
        }

        public Guid SessionId { get; } = Guid.NewGuid();

        public ResearchSession Session { get; }

        public FakeSessions Sessions { get; } = new();

        public FakeTelemetry Telemetry { get; } = new();

        public RecordingAudit Audit { get; } = new();

        public TelemetryIngestService Service { get; }
    }

    private sealed class FakeSessions : ISessionRepository
    {
        private readonly ConcurrentDictionary<Guid, ResearchSession> _store = new();

        public Task AddAsync(ResearchSession session, CancellationToken cancellationToken)
        {
            _store[session.Id] = session;
            return Task.CompletedTask;
        }

        public Task<ResearchSession?> FindAsync(Guid id, CancellationToken cancellationToken) =>
            Task.FromResult(_store.GetValueOrDefault(id));

        public Task UpdateAsync(ResearchSession session, CancellationToken cancellationToken)
        {
            _store[session.Id] = session;
            return Task.CompletedTask;
        }
    }

    private sealed class FakeTelemetry : ITelemetryRepository
    {
        private readonly List<HostnameObservation> _hostnames = [];
        private readonly List<SuppressedTrafficSummary> _suppressed = [];

        public Task AddHostnamesAsync(
            IReadOnlyCollection<HostnameObservation> observations, CancellationToken cancellationToken)
        {
            _hostnames.AddRange(observations);
            return Task.CompletedTask;
        }

        public Task AddSuppressedSummaryAsync(SuppressedTrafficSummary summary, CancellationToken cancellationToken)
        {
            _suppressed.Add(summary);
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<HostnameObservation>> ListForSessionAsync(
            Guid sessionId, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<HostnameObservation>>(
                [.. _hostnames.Where(o => o.SessionId == sessionId)]);

        public Task<IReadOnlyList<SuppressedTrafficSummary>> ListSuppressedForSessionAsync(
            Guid sessionId, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<SuppressedTrafficSummary>>(
                [.. _suppressed.Where(s => s.SessionId == sessionId)]);
    }

    private sealed class RecordingAudit : ITelemetryAuditSink
    {
        public List<(Guid SessionId, string Region, int Count)> Mismatches { get; } = [];

        public List<(Guid SessionId, string Region, int Count)> Unattributable { get; } = [];

        public List<(Guid SessionId, string Claimed, string Actual, int Count)> RegionMismatches { get; } = [];

        public Task SuppressionMismatchAsync(
            Guid sessionId, string region, int itemCount, CancellationToken cancellationToken)
        {
            Mismatches.Add((sessionId, region, itemCount));
            return Task.CompletedTask;
        }

        public Task UnattributableTelemetryAsync(
            Guid sessionId, string region, int itemCount, CancellationToken cancellationToken)
        {
            Unattributable.Add((sessionId, region, itemCount));
            return Task.CompletedTask;
        }

        public Task RegionMismatchAsync(
            Guid sessionId, string claimedRegion, string sessionRegion, int itemCount,
            CancellationToken cancellationToken)
        {
            RegionMismatches.Add((sessionId, claimedRegion, sessionRegion, itemCount));
            return Task.CompletedTask;
        }
    }
}
