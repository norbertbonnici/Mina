using System.Net;
using Mina.ControlPlane.Domain.Sessions;
using Mina.ControlPlane.Domain.Telemetry;

namespace Mina.ManagementUi.Tests;

/// <summary>
/// The browsing-data review screen (M3-8). Off-hours computation, the query guardrail and a
/// suppressed session's structural refusal to expose hostnames are proven exhaustively at the
/// service level (<c>BrowsingDataReviewServiceTests</c>) and again through the control-plane API
/// (<c>BrowsingDataApiTests</c>); what this file adds is the one thing only the real Razor page can
/// prove — that <c>UiPolicies.TelemetryViewer</c> genuinely gates it (and is genuinely distinct from
/// <c>Approver</c>, the whole reason M3-8 introduced a separate role), and that what a node actually
/// reported renders correctly through server-side rendering rather than a JSON contract.
/// </summary>
public sealed class BrowsingDataScreenTests(ManagementUiFactory factory) : IClassFixture<ManagementUiFactory>
{
    private readonly ManagementUiFactory _factory = factory;

    private HttpClient Client(string oid, string? roles, string? upn = null)
    {
        var client = _factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });
        client.DefaultRequestHeaders.Add("X-Test-Oid", oid);
        client.DefaultRequestHeaders.Add("X-Test-Upn", upn ?? $"{oid}@example.org");
        if (!string.IsNullOrEmpty(roles))
        {
            client.DefaultRequestHeaders.Add("X-Test-Roles", roles);
        }

        return client;
    }

    private async Task<ResearchSession> SeedNormalSessionWithHostnameAsync(
        string analystOid, string hostname, DateTimeOffset occurredAt)
    {
        var session = ResearchSession.Issue(
            Guid.NewGuid(), analystOid, $"{analystOid}@example.org", "device-1", "westeurope",
            DateTimeOffset.UtcNow.AddHours(-1), TimeSpan.FromHours(1), $"SERIAL-{analystOid}");
        await _factory.Sessions.AddAsync(session, default);
        await _factory.Telemetry.AddHostnamesAsync(
            [HostnameObservation.Record(session.Id, "westeurope", occurredAt, hostname, 443, 100, 2000, 250)], default);
        return session;
    }

    [Fact]
    public async Task Anonymous_visitors_are_not_served_the_screen()
    {
        var response = await Client("oid-anon", roles: null)
            .GetAsync(new Uri("/browsing-data", UriKind.Relative));

        Assert.NotEqual(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Holding_the_approver_role_alone_does_not_grant_access()
    {
        // The exact property M3-8 introduced a dedicated role to guarantee: approving a
        // sensitive-session request and reading browsing history are different privileges. An
        // approver with no TelemetryViewer role must be refused, not quietly admitted because the
        // two screens feel related.
        await SeedNormalSessionWithHostnameAsync("oid-approver-only", "should-not-be-visible.example", DateTimeOffset.UtcNow);

        var response = await Client("oid-just-approver", "Mina.Approver")
            .GetAsync(new Uri("/browsing-data", UriKind.Relative));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task A_telemetry_viewer_sees_the_hostname_a_node_actually_reported()
    {
        var occurredAt = DateTimeOffset.UtcNow.AddHours(-2);
        await SeedNormalSessionWithHostnameAsync("oid-render-a", "real-target.example", occurredAt);

        var html = await Client("oid-viewer-a", "Mina.TelemetryViewer")
            .GetStringAsync(new Uri("/browsing-data?analyst=oid-render-a", UriKind.Relative));

        Assert.Contains("real-target.example", html, StringComparison.Ordinal);
        Assert.Contains("oid-render-a@example.org", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_sensitive_session_shows_the_suppressed_panel_never_a_hostname()
    {
        var session = ResearchSession.Issue(
            Guid.NewGuid(), "oid-sensitive-screen", "oid-sensitive-screen@example.org", "device-1",
            "westeurope", DateTimeOffset.UtcNow.AddHours(-1), TimeSpan.FromHours(1), "SERIAL-SENS");
        session.MarkSensitive();
        await _factory.Sessions.AddAsync(session, default);

        // Simulates the same hypothetical pipeline bug BrowsingDataReviewServiceTests guards
        // against: a stray hostname row for a session that should have been suppressed.
        await _factory.Telemetry.AddHostnamesAsync(
            [HostnameObservation.Record(
                session.Id, "westeurope", DateTimeOffset.UtcNow.AddMinutes(-30), "must-never-render.example",
                443, 1, 1, 100)],
            default);
        await _factory.Telemetry.AddSuppressedSummaryAsync(
            SuppressedTrafficSummary.Record(session.Id, "westeurope", DateTimeOffset.UtcNow.AddMinutes(-30), 12, 50_000),
            default);

        var html = await Client("oid-viewer-sens", "Mina.TelemetryViewer")
            .GetStringAsync(new Uri("/browsing-data?analyst=oid-sensitive-screen", UriKind.Relative));

        Assert.Contains("Destinations withheld", html, StringComparison.Ordinal);
        Assert.Contains("12 connections", html, StringComparison.Ordinal);
        Assert.DoesNotContain("must-never-render.example", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_over_wide_unscoped_query_shows_the_guardrail_message_not_a_server_error()
    {
        var response = await Client("oid-viewer-guard", "Mina.TelemetryViewer").GetAsync(
            new Uri("/browsing-data?from=2020-01-01&to=2026-09-07", UriKind.Relative));

        response.EnsureSuccessStatusCode(); // the page renders an error banner, not a 500
        var html = await response.Content.ReadAsStringAsync();
        Assert.Contains("must stay within", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Viewing_the_screen_reaches_the_audit_chain_as_telemetry_viewed()
    {
        await SeedNormalSessionWithHostnameAsync("oid-audited-view", "audited.example", DateTimeOffset.UtcNow.AddHours(-1));

        var response = await Client("oid-view-decider", "Mina.TelemetryViewer", upn: "view-decider@example.org")
            .GetAsync(new Uri("/browsing-data?analyst=oid-audited-view", UriKind.Relative));
        response.EnsureSuccessStatusCode();

        var events = await _factory.Audit.ReadRecentAsync(50, default);
        var viewed = Assert.Single(events, e => e.EventType == "telemetry_viewed"
            && e.UserPrincipalName == "view-decider@example.org");

        // Same content-scan discipline as the service and API test suites: the audit trail records
        // that C3 was read, never what was read.
        Assert.DoesNotContain("audited.example", viewed.Data, StringComparison.Ordinal);
    }
}
