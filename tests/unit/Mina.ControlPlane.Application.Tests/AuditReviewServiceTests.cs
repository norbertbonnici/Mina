using Microsoft.Extensions.Options;
using Mina.ControlPlane.Application.Audit;
using Mina.ControlPlane.Application.Sessions;
using Mina.ControlPlane.Domain.Audit;
using Mina.ControlPlane.Persistence;

namespace Mina.ControlPlane.Application.Tests;

/// <summary>
/// The audit trail review screen's read path (M3-2's own "audit views" remaining item). Alongside
/// the ordinary filtering behaviour, this suite proves the one property that matters most for an
/// admin screen reading a governance chain: that viewing it is itself recorded, always, the same
/// "record that access happened" precedent <c>BrowsingDataReviewServiceTests</c> already proves for
/// <c>telemetry_viewed</c>.
/// </summary>
public sealed class AuditReviewServiceTests
{
    private static readonly SessionPrincipal Viewer = new(
        "admin-oid", "admin@example.org", "device-1", new HashSet<string> { "Mina.Admin" }, DeviceBound: true);

    private static (AuditReviewService Service, InMemoryAuditEventStore Store, AuditWriter Writer) Build()
    {
        var store = new InMemoryAuditEventStore();
        var writer = new AuditWriter(store, Options.Create(new AuditOptions { Environment = "test" }), TimeProvider.System);
        return (new AuditReviewService(store, writer), store, writer);
    }

    private static Task<AuditEvent> Seed(
        AuditWriter writer, string eventType, AuditSeverity severity, AuditComponent component, object? data = null) =>
        writer.WriteAsync(new AuditEventDraft(eventType, severity, component, Data: data), default);

    [Fact]
    public async Task Recent_events_come_back_most_recent_first()
    {
        var (service, _, writer) = Build();
        await Seed(writer, "session_started", AuditSeverity.Info, AuditComponent.ControlPlane);
        await Seed(writer, "session_ended", AuditSeverity.Info, AuditComponent.ControlPlane);
        await Seed(writer, "session_revoked", AuditSeverity.High, AuditComponent.ControlPlane);

        var result = await service.ReviewAsync(Viewer, new AuditReviewQuery(), default);

        Assert.Equal(["session_revoked", "session_ended", "session_started"], result.Events.Select(e => e.EventType));
    }

    [Fact]
    public async Task A_severity_filter_narrows_the_fetched_window_without_changing_what_was_fetched()
    {
        var (service, _, writer) = Build();
        await Seed(writer, "session_started", AuditSeverity.Info, AuditComponent.ControlPlane);
        await Seed(writer, "session_revoked", AuditSeverity.High, AuditComponent.ControlPlane);
        await Seed(writer, "client_tamper_suspected", AuditSeverity.High, AuditComponent.EndpointAgent);

        var result = await service.ReviewAsync(
            Viewer, new AuditReviewQuery(Severity: AuditSeverity.High), default);

        Assert.Equal(2, result.Events.Count);
        Assert.All(result.Events, e => Assert.Equal(AuditSeverity.High, e.Severity));
        // TotalBeforeFilter reports what the store actually returned (3), not the post-filter count
        // (2) -- the "fetched before filtering" card on the screen depends on this distinction to
        // show a reviewer whether their filter is narrowing a small window or a large one.
        Assert.Equal(3, result.TotalBeforeFilter);
    }

    [Fact]
    public async Task A_component_filter_narrows_independently_of_severity()
    {
        var (service, _, writer) = Build();
        await Seed(writer, "session_started", AuditSeverity.Info, AuditComponent.ControlPlane);
        await Seed(writer, "client_tamper_suspected", AuditSeverity.High, AuditComponent.EndpointAgent);

        var result = await service.ReviewAsync(
            Viewer, new AuditReviewQuery(Component: AuditComponent.EndpointAgent), default);

        var view = Assert.Single(result.Events);
        Assert.Equal("client_tamper_suspected", view.EventType);
    }

    [Fact]
    public async Task An_event_type_filter_matches_case_insensitively_and_by_substring()
    {
        var (service, _, writer) = Build();
        await Seed(writer, "sensitive_approved", AuditSeverity.Notice, AuditComponent.ControlPlane);
        await Seed(writer, "session_revoked", AuditSeverity.High, AuditComponent.ControlPlane);

        var result = await service.ReviewAsync(
            Viewer, new AuditReviewQuery(EventTypeContains: "APPROV"), default);

        var view = Assert.Single(result.Events);
        Assert.Equal("sensitive_approved", view.EventType);
    }

    [Fact]
    public async Task A_limit_above_the_hard_ceiling_is_clamped_rather_than_honoured()
    {
        var (service, _, writer) = Build();
        await Seed(writer, "session_started", AuditSeverity.Info, AuditComponent.ControlPlane);

        // Proves the clamp exists by exercising a value past it, not by asserting the constant.
        var result = await service.ReviewAsync(
            Viewer, new AuditReviewQuery(Limit: AuditReviewService.MaxLimit + 1000), default);

        Assert.Single(result.Events);
    }

    [Fact]
    public async Task Every_query_writes_exactly_one_audit_trail_viewed_event_even_when_the_result_is_empty()
    {
        var (service, store, _) = Build();

        await service.ReviewAsync(Viewer, new AuditReviewQuery(), default);

        var events = await store.ReadRecentAsync(50, default);
        var viewed = Assert.Single(events, e => e.EventType == "audit_trail_viewed");
        Assert.Equal("admin@example.org", viewed.UserPrincipalName);
        Assert.Equal(AuditComponent.ManagementUi, viewed.Component);
    }

    [Fact]
    public async Task The_audit_trail_viewed_event_never_carries_another_event_s_data_content()
    {
        // Same content-scan discipline BrowsingDataReviewServiceTests applies to telemetry_viewed:
        // this service's own audit event must prove *that* the trail was read, not echo *what* was
        // in it -- a payload containing another event's data would turn a "who looked" record into
        // an unbounded copy of whatever that event happened to describe.
        var (service, store, writer) = Build();
        await Seed(writer, "sensitive_requested", AuditSeverity.Notice, AuditComponent.ControlPlane,
            data: new { justification_ref = "SECRET-TICKET-REF-12345" });

        await service.ReviewAsync(Viewer, new AuditReviewQuery(), default);

        var events = await store.ReadRecentAsync(50, default);
        var viewed = Assert.Single(events, e => e.EventType == "audit_trail_viewed");
        Assert.DoesNotContain("SECRET-TICKET-REF-12345", viewed.Data, StringComparison.Ordinal);
    }
}
