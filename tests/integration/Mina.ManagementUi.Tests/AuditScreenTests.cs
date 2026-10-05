using System.Net;
using Microsoft.Extensions.Options;
using Mina.ControlPlane.Application.Audit;
using Mina.ControlPlane.Domain.Audit;

namespace Mina.ManagementUi.Tests;

/// <summary>
/// The audit trail screen (M3-2's own "audit views" remaining item). Filtering and the
/// audit-of-access guarantee are proven exhaustively at the service level
/// (<c>AuditReviewServiceTests</c>); what this file adds is what only the real Razor page can
/// prove -- that <c>UiPolicies.Admin</c> genuinely gates it (and is genuinely distinct from
/// <c>Approver</c>, matching the same separation <c>AuditEndpoints</c>' own <c>AdminPolicy</c>
/// enforces on the API side), and that a real event actually renders through server-side rendering.
/// </summary>
public sealed class AuditScreenTests(ManagementUiFactory factory) : IClassFixture<ManagementUiFactory>
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

    /// <summary>
    /// Writes a real, properly chained event straight through <see cref="AuditWriter"/> onto the
    /// factory's shared in-memory store -- the same store the app under test reads from -- rather
    /// than fabricating an <see cref="AuditEvent"/> by hand, which would need to guess at the
    /// sequence/hash chain the store actually expects.
    /// </summary>
    private Task<AuditEvent> Seed(string eventType, AuditSeverity severity, AuditComponent component, object? data = null) =>
        new AuditWriter(_factory.Audit, Options.Create(new AuditOptions { Environment = "test" }), TimeProvider.System)
            .WriteAsync(new AuditEventDraft(eventType, severity, component, Data: data), default);

    [Fact]
    public async Task Anonymous_visitors_are_not_served_the_screen()
    {
        var response = await Client("oid-anon", roles: null).GetAsync(new Uri("/audit", UriKind.Relative));

        Assert.NotEqual(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Holding_the_approver_role_alone_does_not_grant_access()
    {
        // The exact property AuditEndpoints' own AdminPolicy already enforces on the API side:
        // approving requests and reading the governance trail are different privileges. An approver
        // with no Admin role must be refused here too, not quietly admitted because the screens
        // feel related.
        var response = await Client("oid-just-approver", "Mina.Approver")
            .GetAsync(new Uri("/audit", UriKind.Relative));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task An_admin_sees_an_event_the_trail_actually_holds()
    {
        await Seed("client_tamper_suspected", AuditSeverity.High, AuditComponent.EndpointAgent,
            data: new { indicator = "wfp_rule_missing" });

        var html = await Client("oid-admin-a", "Mina.Admin").GetStringAsync(new Uri("/audit", UriKind.Relative));

        Assert.Contains("client_tamper_suspected", html, StringComparison.Ordinal);
        Assert.Contains("EndpointAgent", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_severity_filter_hides_events_of_other_severities()
    {
        await Seed("session_started", AuditSeverity.Info, AuditComponent.ControlPlane);
        await Seed("session_revoked", AuditSeverity.High, AuditComponent.ControlPlane);

        var html = await Client("oid-admin-b", "Mina.Admin")
            .GetStringAsync(new Uri("/audit?severity=High", UriKind.Relative));

        Assert.Contains("session_revoked", html, StringComparison.Ordinal);
        Assert.DoesNotContain("session_started", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Viewing_the_screen_reaches_the_audit_chain_as_audit_trail_viewed()
    {
        var response = await Client("oid-view-decider", "Mina.Admin", upn: "audit-viewer@example.org")
            .GetAsync(new Uri("/audit", UriKind.Relative));
        response.EnsureSuccessStatusCode();

        var events = await _factory.Audit.ReadRecentAsync(50, default);
        var viewed = Assert.Single(events, e => e.EventType == "audit_trail_viewed"
            && e.UserPrincipalName == "audit-viewer@example.org");
        Assert.Equal(AuditComponent.ManagementUi, viewed.Component);
    }
}
