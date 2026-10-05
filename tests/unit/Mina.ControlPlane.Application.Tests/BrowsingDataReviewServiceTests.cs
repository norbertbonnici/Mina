using System.Text.Json;
using Microsoft.Extensions.Options;
using Mina.ControlPlane.Application.Sessions;
using Mina.ControlPlane.Application.Telemetry;
using Mina.ControlPlane.Domain.Sessions;
using Mina.ControlPlane.Domain.Telemetry;
using Mina.ControlPlane.Persistence;

namespace Mina.ControlPlane.Application.Tests;

/// <summary>
/// Browsing-data review (M3-8, threat N10). Alongside the ordinary behaviour, this suite is
/// concerned with two properties an off-the-shelf test would not think to ask for: that a
/// suppressed session's destinations can never reach a view model even if something upstream put
/// them within reach, and that the one audit event this service writes never itself carries a
/// hostname — the same content-scan discipline AC-014 already applies to the SigNoz scrub pipeline.
/// </summary>
public sealed class BrowsingDataReviewServiceTests
{
    private static readonly SessionPrincipal Viewer = new(
        "viewer-oid", "reviewer@example.org", "device-1", new HashSet<string> { "Mina.Approver" }, DeviceBound: true);

    private static readonly DateTimeOffset WindowFrom = new(2026, 9, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset WindowTo = new(2026, 9, 30, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void The_shipped_configuration_has_office_hours_flagging_disabled()
    {
        // Guards the default itself, the same reason TelemetryRetentionServiceTests does: an
        // off-hours flag is a judgement about an analyst, and it must not start being made on a
        // definition of "office hours" nobody configured.
        Assert.False(new OfficeHoursOptions().IsConfigured);
    }

    [Fact]
    public async Task Unconfigured_office_hours_flags_nothing_however_unusual_the_timing()
    {
        var (session, sessions, store) = await SeedNormalSessionAsync();
        await store.AddHostnamesAsync(
            [HostnameObservation.Record(session.Id, "spaincentral", new DateTimeOffset(2026, 9, 6, 3, 0, 0, TimeSpan.Zero),
                "example.test", 443, 1, 1, 100)],
            default);

        var result = await Service(sessions, store, new RecordingTelemetryAudit(), OfficeHours(null))
            .ReviewAsync(Viewer, new BrowsingDataQuery(session.UserObjectId, WindowFrom, WindowTo), default);

        var view = Assert.Single(result.Sessions);
        Assert.All(view.Hostnames, h => Assert.False(h.IsOffHours));
        Assert.Equal(0, result.OffHoursFlaggedCount);
    }

    [Fact]
    public async Task A_connection_outside_the_configured_window_is_flagged_and_one_inside_is_not()
    {
        var (session, sessions, store) = await SeedNormalSessionAsync();
        // 2026-09-07 is a Monday.
        var inHours = new DateTimeOffset(2026, 9, 7, 8, 0, 0, TimeSpan.FromHours(2));   // 08:00 local (CEST, Europe/Malta)
        var offHours = new DateTimeOffset(2026, 9, 7, 21, 0, 0, TimeSpan.FromHours(2)); // 21:00 local
        await store.AddHostnamesAsync(
            [
                HostnameObservation.Record(session.Id, "spaincentral", inHours, "in-hours.example", 443, 1, 1, 100),
                HostnameObservation.Record(session.Id, "spaincentral", offHours, "off-hours.example", 443, 1, 1, 100),
            ],
            default);

        var result = await Service(sessions, store, new RecordingTelemetryAudit(), OfficeHours(WeekdaysOffice))
            .ReviewAsync(Viewer, new BrowsingDataQuery(session.UserObjectId, WindowFrom, WindowTo), default);

        var view = Assert.Single(result.Sessions);
        Assert.False(Assert.Single(view.Hostnames, h => h.Hostname == "in-hours.example").IsOffHours);
        Assert.True(Assert.Single(view.Hostnames, h => h.Hostname == "off-hours.example").IsOffHours);
        Assert.Equal(1, result.OffHoursFlaggedCount);
    }

    [Fact]
    public async Task A_connection_on_a_day_outside_the_configured_days_is_flagged_regardless_of_time_of_day()
    {
        var (session, sessions, store) = await SeedNormalSessionAsync();
        var saturdayAtNoon = new DateTimeOffset(2026, 9, 12, 12, 0, 0, TimeSpan.FromHours(2)); // Saturday
        await store.AddHostnamesAsync(
            [HostnameObservation.Record(session.Id, "spaincentral", saturdayAtNoon, "weekend.example", 443, 1, 1, 100)],
            default);

        var result = await Service(sessions, store, new RecordingTelemetryAudit(), OfficeHours(WeekdaysOffice))
            .ReviewAsync(Viewer, new BrowsingDataQuery(session.UserObjectId, WindowFrom, WindowTo), default);

        Assert.True(Assert.Single(Assert.Single(result.Sessions).Hostnames).IsOffHours);
    }

    [Fact]
    public async Task The_office_hours_boundary_is_exact_start_inclusive_end_exclusive()
    {
        var (session, sessions, store) = await SeedNormalSessionAsync();
        // Monday 2026-09-07, window 07:00-19:00 Europe/Malta (CEST, UTC+2 in September).
        var atStart = new DateTimeOffset(2026, 9, 7, 7, 0, 0, TimeSpan.FromHours(2));
        var atEnd = new DateTimeOffset(2026, 9, 7, 19, 0, 0, TimeSpan.FromHours(2));
        await store.AddHostnamesAsync(
            [
                HostnameObservation.Record(session.Id, "spaincentral", atStart, "at-start.example", 443, 1, 1, 100),
                HostnameObservation.Record(session.Id, "spaincentral", atEnd, "at-end.example", 443, 1, 1, 100),
            ],
            default);

        var result = await Service(sessions, store, new RecordingTelemetryAudit(), OfficeHours(WeekdaysOffice))
            .ReviewAsync(Viewer, new BrowsingDataQuery(session.UserObjectId, WindowFrom, WindowTo), default);

        var view = Assert.Single(result.Sessions);
        Assert.False(Assert.Single(view.Hostnames, h => h.Hostname == "at-start.example").IsOffHours);
        Assert.True(Assert.Single(view.Hostnames, h => h.Hostname == "at-end.example").IsOffHours);
    }

    [Fact]
    public async Task Office_hours_conversion_accounts_for_daylight_saving()
    {
        // The same wall-clock UTC hour (05:30) falls inside a 07:00-19:00 Europe/Malta window in
        // summer (CEST, UTC+2 -> 07:30 local) and outside it in winter (CET, UTC+1 -> 06:30 local).
        // A fixed-offset implementation would treat the two identically and fail this.
        var (session, sessions, store) = await SeedNormalSessionAsync();
        var summer0530Utc = new DateTimeOffset(2026, 7, 6, 5, 30, 0, TimeSpan.Zero);   // Monday, CEST
        var winter0530Utc = new DateTimeOffset(2026, 2, 2, 5, 30, 0, TimeSpan.Zero);   // Monday, CET
        await store.AddHostnamesAsync(
            [
                HostnameObservation.Record(session.Id, "spaincentral", summer0530Utc, "summer.example", 443, 1, 1, 100),
                HostnameObservation.Record(session.Id, "spaincentral", winter0530Utc, "winter.example", 443, 1, 1, 100),
            ],
            default);

        var result = await Service(sessions, store, new RecordingTelemetryAudit(), OfficeHours(WeekdaysOffice))
            .ReviewAsync(
                Viewer,
                new BrowsingDataQuery(
                    session.UserObjectId,
                    new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero),
                    new DateTimeOffset(2026, 12, 31, 0, 0, 0, TimeSpan.Zero)),
                default);

        var view = Assert.Single(result.Sessions);
        Assert.False(Assert.Single(view.Hostnames, h => h.Hostname == "summer.example").IsOffHours);
        Assert.True(Assert.Single(view.Hostnames, h => h.Hostname == "winter.example").IsOffHours);
    }

    [Fact]
    public async Task Suppressed_sessions_never_expose_hostnames_even_when_stray_rows_exist_for_them()
    {
        // Simulates a hypothetical bug elsewhere in the pipeline that wrote hostname rows for a
        // session that should have been suppressed. The service must not surface them regardless --
        // a Sensitive session's view is built from SuppressedTrafficSummary alone, structurally, not
        // by filtering hostnames out of a result that includes them.
        var sessions = new InMemorySessionRepository();
        var store = new InMemoryTelemetryRepository();
        var session = ResearchSession.Issue(
            Guid.NewGuid(), "analyst-oid", "analyst@example.org", "device-1", "spaincentral",
            new DateTimeOffset(2026, 9, 7, 9, 0, 0, TimeSpan.Zero), TimeSpan.FromMinutes(60), "cert-1");
        session.MarkSensitive();
        await sessions.AddAsync(session, default);

        await store.AddHostnamesAsync(
            [HostnameObservation.Record(
                session.Id, "spaincentral", new DateTimeOffset(2026, 9, 7, 10, 0, 0, TimeSpan.Zero),
                "should-never-appear.example", 443, 1, 1, 100)],
            default);
        await store.AddSuppressedSummaryAsync(
            SuppressedTrafficSummary.Record(
                session.Id, "spaincentral", new DateTimeOffset(2026, 9, 7, 10, 0, 0, TimeSpan.Zero), 4, 900),
            default);

        var result = await Service(sessions, store, new RecordingTelemetryAudit(), OfficeHours(null))
            .ReviewAsync(Viewer, new BrowsingDataQuery(session.UserObjectId, WindowFrom, WindowTo), default);

        var view = Assert.Single(result.Sessions);
        Assert.Empty(view.Hostnames);
        Assert.Single(view.SuppressedIntervals);
        Assert.Equal(1, result.SensitiveSessionCount);
        Assert.Equal(4, result.ConnectionsTotal);
    }

    [Fact]
    public async Task A_multi_session_query_does_not_leak_a_suppressed_sessions_hostname_alongside_a_normal_ones()
    {
        // The single-session version above proves the structural refusal for one session at a time.
        // An unscoped query resolves several sessions in one ReviewAsync call and fetches their
        // telemetry through the batched ListForSessionsAsync/ListSuppressedForSessionsAsync -- this
        // proves that batching a suppressed session alongside a normal one in the same call does not
        // let either leak into the other's view (M3-7).
        var sessions = new InMemorySessionRepository();
        var store = new InMemoryTelemetryRepository();

        var normal = await AddSessionAsync(sessions, "analyst-normal", "normal@example.org");
        await store.AddHostnamesAsync(
            [HostnameObservation.Record(
                normal.Id, "spaincentral", new DateTimeOffset(2026, 9, 7, 10, 0, 0, TimeSpan.Zero),
                "visible-target.example", 443, 1, 1, 100)],
            default);

        var sensitive = ResearchSession.Issue(
            Guid.NewGuid(), "analyst-sensitive", "sensitive@example.org", "device-1", "spaincentral",
            new DateTimeOffset(2026, 9, 7, 9, 0, 0, TimeSpan.Zero), TimeSpan.FromMinutes(60), "cert-sensitive");
        sensitive.MarkSensitive();
        await sessions.AddAsync(sensitive, default);
        await store.AddHostnamesAsync(
            [HostnameObservation.Record(
                sensitive.Id, "spaincentral", new DateTimeOffset(2026, 9, 7, 10, 0, 0, TimeSpan.Zero),
                "must-stay-suppressed.example", 443, 1, 1, 100)],
            default);
        await store.AddSuppressedSummaryAsync(
            SuppressedTrafficSummary.Record(
                sensitive.Id, "spaincentral", new DateTimeOffset(2026, 9, 7, 10, 0, 0, TimeSpan.Zero), 3, 600),
            default);

        var result = await Service(sessions, store, new RecordingTelemetryAudit(), OfficeHours(null))
            .ReviewAsync(Viewer, new BrowsingDataQuery(AnalystUserObjectId: null, WindowFrom, WindowTo), default);

        Assert.Equal(2, result.Sessions.Count);

        var normalView = Assert.Single(result.Sessions, v => v.SessionId == normal.Id);
        Assert.Equal("visible-target.example", Assert.Single(normalView.Hostnames).Hostname);
        Assert.Empty(normalView.SuppressedIntervals);

        var sensitiveView = Assert.Single(result.Sessions, v => v.SessionId == sensitive.Id);
        Assert.Empty(sensitiveView.Hostnames);
        Assert.Single(sensitiveView.SuppressedIntervals);

        var serialized = JsonSerializer.Serialize(result);
        Assert.DoesNotContain("must-stay-suppressed.example", serialized, StringComparison.Ordinal);
        Assert.Contains("visible-target.example", serialized, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_suppressed_sessions_id_is_never_passed_to_the_hostname_query_at_all()
    {
        // The two tests above prove the view model never carries a suppressed session's hostnames.
        // This one proves the stronger property the design commits to (BACKLOG M3-8): the refusal
        // happens at the repository call, so the hostnames never leave storage on this path in the
        // first place -- not "fetched and then dropped". A spy wraps the store and records exactly
        // which session ids each batched query was asked for.
        var sessions = new InMemorySessionRepository();
        var spy = new RecordingTelemetryRepository(new InMemoryTelemetryRepository());

        var normal = await AddSessionAsync(sessions, "analyst-normal", "normal@example.org");
        var sensitive = ResearchSession.Issue(
            Guid.NewGuid(), "analyst-sensitive", "sensitive@example.org", "device-1", "spaincentral",
            new DateTimeOffset(2026, 9, 7, 9, 0, 0, TimeSpan.Zero), TimeSpan.FromMinutes(60), "cert-sensitive");
        sensitive.MarkSensitive();
        await sessions.AddAsync(sensitive, default);
        await spy.AddSuppressedSummaryAsync(
            SuppressedTrafficSummary.Record(
                sensitive.Id, "spaincentral", new DateTimeOffset(2026, 9, 7, 10, 0, 0, TimeSpan.Zero), 3, 600),
            default);

        await Service(sessions, spy, new RecordingTelemetryAudit(), OfficeHours(null))
            .ReviewAsync(Viewer, new BrowsingDataQuery(AnalystUserObjectId: null, WindowFrom, WindowTo), default);

        var hostnameQuery = Assert.Single(spy.HostnameQueries);
        Assert.Contains(normal.Id, hostnameQuery);
        Assert.DoesNotContain(sensitive.Id, hostnameQuery);

        // And the converse: the aggregate query is scoped to sensitive sessions only, so a normal
        // session's (nonexistent) summaries are not something a reviewer's query even asks for.
        var suppressedQuery = Assert.Single(spy.SuppressedQueries);
        Assert.Contains(sensitive.Id, suppressedQuery);
        Assert.DoesNotContain(normal.Id, suppressedQuery);
    }

    [Fact]
    public async Task A_query_naming_no_analyst_must_stay_within_the_range_limit()
    {
        var sessions = new InMemorySessionRepository();
        var store = new InMemoryTelemetryRepository();
        var service = Service(sessions, store, new RecordingTelemetryAudit(), OfficeHours(null));

        var tooWide = new BrowsingDataQuery(
            AnalystUserObjectId: null,
            From: new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero),
            To: new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero)
                .AddDays(BrowsingDataReviewService.MaxUnscopedRangeDays + 1));

        await Assert.ThrowsAsync<BrowsingDataQueryException>(() => service.ReviewAsync(Viewer, tooWide, default));
    }

    [Fact]
    public async Task A_single_analyst_query_has_no_range_limit()
    {
        var (session, sessions, store) = await SeedNormalSessionAsync();
        var wideButScoped = new BrowsingDataQuery(
            session.UserObjectId,
            new DateTimeOffset(2000, 1, 1, 0, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero));

        var result = await Service(sessions, store, new RecordingTelemetryAudit(), OfficeHours(null))
            .ReviewAsync(Viewer, wideButScoped, default);

        Assert.NotNull(result); // did not throw
    }

    [Fact]
    public async Task The_range_end_must_be_after_the_start()
    {
        var sessions = new InMemorySessionRepository();
        var store = new InMemoryTelemetryRepository();
        var service = Service(sessions, store, new RecordingTelemetryAudit(), OfficeHours(null));

        var backwards = new BrowsingDataQuery("analyst-oid", WindowTo, WindowFrom);
        await Assert.ThrowsAsync<BrowsingDataQueryException>(() => service.ReviewAsync(Viewer, backwards, default));
    }

    [Fact]
    public async Task Every_query_writes_exactly_one_audit_event_that_never_contains_a_hostname()
    {
        var (session, sessions, store) = await SeedNormalSessionAsync();
        const string secretHostname = "veryunique-research-target.example";
        await store.AddHostnamesAsync(
            [HostnameObservation.Record(
                session.Id, "spaincentral", new DateTimeOffset(2026, 9, 7, 10, 0, 0, TimeSpan.Zero),
                secretHostname, 443, 1, 1, 100)],
            default);

        var audit = new RecordingTelemetryAudit();
        await Service(sessions, store, audit, OfficeHours(null))
            .ReviewAsync(Viewer, new BrowsingDataQuery(session.UserObjectId, WindowFrom, WindowTo), default);

        var recorded = Assert.Single(audit.Viewed);
        Assert.Equal(Viewer.UserPrincipalName, recorded.ViewerUpn);
        Assert.Equal(Viewer.UserObjectId, recorded.ViewerObjectId);
        Assert.Equal(1, recorded.SessionCount);

        // Content-scan the whole recorded event, the way AC-014 scans the SigNoz pipeline: proving
        // "never a hostname" by inspecting the fields that exist is only as strong as the list of
        // fields someone remembered to check.
        var serialized = JsonSerializer.Serialize(recorded);
        Assert.DoesNotContain(secretHostname, serialized, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_empty_result_still_writes_the_audit_event()
    {
        var sessions = new InMemorySessionRepository();
        var store = new InMemoryTelemetryRepository();
        var audit = new RecordingTelemetryAudit();

        var result = await Service(sessions, store, audit, OfficeHours(null))
            .ReviewAsync(Viewer, new BrowsingDataQuery("nobody-has-this-oid", WindowFrom, WindowTo), default);

        Assert.Empty(result.Sessions);
        Assert.Single(audit.Viewed);
    }

    [Fact]
    public async Task Off_hours_only_keeps_only_sessions_with_flagged_activity()
    {
        var sessions = new InMemorySessionRepository();
        var store = new InMemoryTelemetryRepository();

        var flaggedSession = await AddSessionAsync(sessions, "analyst-a", "a@example.org");
        var quietSession = await AddSessionAsync(sessions, "analyst-b", "b@example.org");
        var offHours = new DateTimeOffset(2026, 9, 7, 22, 0, 0, TimeSpan.FromHours(2)); // Monday 22:00 local
        var inHours = new DateTimeOffset(2026, 9, 7, 10, 0, 0, TimeSpan.FromHours(2));  // Monday 10:00 local
        await store.AddHostnamesAsync(
            [HostnameObservation.Record(flaggedSession.Id, "spaincentral", offHours, "late.example", 443, 1, 1, 100)], default);
        await store.AddHostnamesAsync(
            [HostnameObservation.Record(quietSession.Id, "spaincentral", inHours, "normal.example", 443, 1, 1, 100)], default);

        var result = await Service(sessions, store, new RecordingTelemetryAudit(), OfficeHours(WeekdaysOffice))
            .ReviewAsync(
                Viewer, new BrowsingDataQuery(AnalystUserObjectId: null, WindowFrom, WindowTo, OffHoursOnly: true), default);

        var view = Assert.Single(result.Sessions);
        Assert.Equal(flaggedSession.Id, view.SessionId);
    }

    [Theory]
    [InlineData(true, false, false, false)]
    [InlineData(false, true, false, false)]
    [InlineData(false, false, true, false)]
    [InlineData(false, false, false, true)]
    public void Partially_configured_office_hours_is_rejected(bool tz, bool days, bool start, bool end)
    {
        var options = new OfficeHoursOptions
        {
            Timezone = tz ? "Europe/Malta" : null,
            Days = days ? [DayOfWeek.Monday] : [],
            StartLocal = start ? new TimeOnly(7, 0) : null,
            EndLocal = end ? new TimeOnly(19, 0) : null,
        };

        Assert.NotEmpty(options.Validate());
    }

    [Fact]
    public void Start_on_or_after_end_is_rejected()
    {
        var options = new OfficeHoursOptions
        {
            Timezone = "Europe/Malta",
            Days = [DayOfWeek.Monday],
            StartLocal = new TimeOnly(19, 0),
            EndLocal = new TimeOnly(7, 0),
        };

        Assert.NotEmpty(options.Validate());
    }

    [Fact]
    public void An_unrecognised_timezone_is_rejected()
    {
        var options = new OfficeHoursOptions
        {
            Timezone = "Not/A_Real_Zone",
            Days = [DayOfWeek.Monday],
            StartLocal = new TimeOnly(7, 0),
            EndLocal = new TimeOnly(19, 0),
        };

        Assert.NotEmpty(options.Validate());
    }

    [Fact]
    public void A_fully_configured_window_validates_clean() => Assert.Empty(WeekdaysOffice.Validate());

    private static OfficeHoursOptions WeekdaysOffice => new()
    {
        Timezone = "Europe/Malta",
        Days = [DayOfWeek.Monday, DayOfWeek.Tuesday, DayOfWeek.Wednesday, DayOfWeek.Thursday, DayOfWeek.Friday],
        StartLocal = new TimeOnly(7, 0),
        EndLocal = new TimeOnly(19, 0),
    };

    private static IOptions<OfficeHoursOptions> OfficeHours(OfficeHoursOptions? options) =>
        Options.Create(options ?? new OfficeHoursOptions());

    private static async Task<(ResearchSession Session, InMemorySessionRepository Sessions, InMemoryTelemetryRepository Store)>
        SeedNormalSessionAsync()
    {
        var sessions = new InMemorySessionRepository();
        var store = new InMemoryTelemetryRepository();
        var session = await AddSessionAsync(sessions, "analyst-oid", "analyst@example.org");
        return (session, sessions, store);
    }

    private static async Task<ResearchSession> AddSessionAsync(
        InMemorySessionRepository sessions, string userObjectId, string upn)
    {
        var session = ResearchSession.Issue(
            Guid.NewGuid(), userObjectId, upn, "device-1", "spaincentral",
            new DateTimeOffset(2026, 9, 7, 9, 0, 0, TimeSpan.Zero), TimeSpan.FromMinutes(60), $"cert-{userObjectId}");
        await sessions.AddAsync(session, default);
        return session;
    }

    private static BrowsingDataReviewService Service(
        ISessionQueries sessions, ITelemetryRepository store, ITelemetryAuditSink audit, IOptions<OfficeHoursOptions> officeHours) =>
        new(sessions, store, audit, officeHours);

    /// <summary>Records which session ids each batched read was asked for; everything else delegates.</summary>
    private sealed class RecordingTelemetryRepository(ITelemetryRepository inner) : ITelemetryRepository
    {
        public List<IReadOnlyCollection<Guid>> HostnameQueries { get; } = [];
        public List<IReadOnlyCollection<Guid>> SuppressedQueries { get; } = [];

        public Task AddHostnamesAsync(IReadOnlyCollection<HostnameObservation> observations, CancellationToken cancellationToken) =>
            inner.AddHostnamesAsync(observations, cancellationToken);

        public Task AddSuppressedSummaryAsync(SuppressedTrafficSummary summary, CancellationToken cancellationToken) =>
            inner.AddSuppressedSummaryAsync(summary, cancellationToken);

        public Task<IReadOnlyList<HostnameObservation>> ListForSessionAsync(Guid sessionId, CancellationToken cancellationToken) =>
            inner.ListForSessionAsync(sessionId, cancellationToken);

        public Task<IReadOnlyList<SuppressedTrafficSummary>> ListSuppressedForSessionAsync(Guid sessionId, CancellationToken cancellationToken) =>
            inner.ListSuppressedForSessionAsync(sessionId, cancellationToken);

        public Task<IReadOnlyList<HostnameObservation>> ListForSessionsAsync(
            IReadOnlyCollection<Guid> sessionIds, CancellationToken cancellationToken)
        {
            HostnameQueries.Add([.. sessionIds]);
            return inner.ListForSessionsAsync(sessionIds, cancellationToken);
        }

        public Task<IReadOnlyList<SuppressedTrafficSummary>> ListSuppressedForSessionsAsync(
            IReadOnlyCollection<Guid> sessionIds, CancellationToken cancellationToken)
        {
            SuppressedQueries.Add([.. sessionIds]);
            return inner.ListSuppressedForSessionsAsync(sessionIds, cancellationToken);
        }

        public Task<int> DeleteHostnamesBeforeAsync(DateTimeOffset cutoff, int limit, CancellationToken cancellationToken) =>
            inner.DeleteHostnamesBeforeAsync(cutoff, limit, cancellationToken);

        public Task<int> DeleteSuppressedSummariesBeforeAsync(DateTimeOffset cutoff, int limit, CancellationToken cancellationToken) =>
            inner.DeleteSuppressedSummariesBeforeAsync(cutoff, limit, cancellationToken);
    }

    private sealed class RecordingTelemetryAudit : ITelemetryAuditSink
    {
        public List<(string ViewerUpn, string ViewerObjectId, string? TargetAnalystUpn, DateTimeOffset From, DateTimeOffset To, int SessionCount)> Viewed { get; } = [];

        public Task SuppressionMismatchAsync(
            Guid sessionId, string region, int itemCount, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task UnattributableTelemetryAsync(
            Guid sessionId, string region, int itemCount, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task RegionMismatchAsync(
            Guid sessionId, string claimedRegion, string sessionRegion, int itemCount,
            CancellationToken cancellationToken) => Task.CompletedTask;

        public Task RetentionAppliedAsync(
            DateTimeOffset cutoff, int hostnames, int suppressedSummaries, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task TelemetryViewedAsync(
            string viewerUpn, string viewerObjectId, string? targetAnalystUpn,
            DateTimeOffset rangeFrom, DateTimeOffset rangeTo, int sessionCount, CancellationToken cancellationToken)
        {
            Viewed.Add((viewerUpn, viewerObjectId, targetAnalystUpn, rangeFrom, rangeTo, sessionCount));
            return Task.CompletedTask;
        }
    }
}
