using System.Net;
using System.Text.RegularExpressions;
using Mina.ControlPlane.Domain.Audit;
using Mina.ControlPlane.Domain.SensitiveSessions;
using Mina.ControlPlane.Domain.Sessions;

namespace Mina.ManagementUi.Tests;

/// <summary>
/// The approvals screen and its decision endpoints. The rules themselves are covered at the service
/// layer; what these assert is that the screen shows the right people the right things, and that the
/// same rules still bind when a decision arrives as a form post rather than an API call.
/// </summary>
public sealed class ApprovalScreenTests(ManagementUiFactory factory) : IClassFixture<ManagementUiFactory>
{
    private static readonly SensitiveSessionPolicy Policy = new(TimeSpan.FromHours(4));

    private readonly ManagementUiFactory _factory = factory;

    private HttpClient Client(string oid, string? roles, string? upn = null)
    {
        var client = _factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });
        client.DefaultRequestHeaders.Add("X-Test-Oid", oid);
        client.DefaultRequestHeaders.Add("X-Test-Upn", upn ?? $"{oid}@fiaumalta.org");
        if (!string.IsNullOrEmpty(roles))
        {
            client.DefaultRequestHeaders.Add("X-Test-Roles", roles);
        }

        return client;
    }

    private async Task<SensitiveSessionRequest> SeedPendingAsync(
        string analystOid = "oid-analyst", string reference = "CASE-2026-0042")
    {
        var sessionId = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;
        var session = ResearchSession.Issue(
            sessionId, analystOid, $"{analystOid}@fiaumalta.org", "device-1", "westeurope",
            now, TimeSpan.FromHours(1), "SERIAL-1");
        await _factory.Sessions.AddAsync(session, default);

        var request = SensitiveSessionRequest.Create(
            Guid.NewGuid(), sessionId, analystOid, $"{analystOid}@fiaumalta.org",
            reference, TimeSpan.FromHours(1), Policy, now);
        await _factory.Requests.AddAsync(request, default);
        return request;
    }

    [Fact]
    public async Task Anonymous_visitors_are_not_served_the_console()
    {
        using var anonymous = _factory.CreateClient(
            new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        var response = await anonymous.GetAsync(new Uri("/approvals", UriKind.Relative));

        Assert.NotEqual(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task An_approver_sees_the_pending_request()
    {
        var request = await SeedPendingAsync(reference: "CASE-VISIBLE");

        var html = await Client("oid-approver", "Mina.Approver").GetStringAsync(
            new Uri("/approvals", UriKind.Relative));

        Assert.Contains("CASE-VISIBLE", html, StringComparison.Ordinal);
        Assert.Contains(request.RequesterUpn, html, StringComparison.Ordinal);
        Assert.Contains("Approve", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_analyst_without_the_approver_role_never_receives_the_queue()
    {
        await SeedPendingAsync(reference: "CASE-HIDDEN");

        var response = await Client("oid-plain-analyst", "Mina.Analyst")
            .GetAsync(new Uri("/approvals", UriKind.Relative));

        // The page is refused outright rather than rendered with its contents hidden, so no
        // pending request — nor who raised it — reaches someone without the approver role.
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.DoesNotContain("CASE-HIDDEN", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Posting_a_decision_without_the_approver_role_is_forbidden()
    {
        var request = await SeedPendingAsync("oid-forbidden");
        using var analyst = Client("oid-plain", "Mina.Analyst");

        // No antiforgery token is obtainable without the role, because the form is never served.
        // Authorization runs ahead of antiforgery, so the post is refused on the role, not the token.
        using var content = new FormUrlEncodedContent(
            [new KeyValuePair<string, string>("requestId", request.Id.ToString()),
             new KeyValuePair<string, string>("ttlMinutes", "60")]);
        var response = await analyst.PostAsync(new Uri("/approvals/approve", UriKind.Relative), content);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var stored = await _factory.Requests.FindAsync(request.Id, default);
        Assert.Equal(SensitiveSessionState.Requested, stored!.State);
    }

    [Fact]
    public async Task An_approver_can_approve_from_the_screen()
    {
        var request = await SeedPendingAsync("oid-approve-me");
        using var approver = Client("oid-decider", "Mina.Approver");

        var response = await PostDecisionAsync(approver, "/approvals/approve", request.Id, 60);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Contains("done=", response.Headers.Location!.ToString(), StringComparison.Ordinal);

        var stored = await _factory.Requests.FindAsync(request.Id, default);
        Assert.Equal(SensitiveSessionState.Approved, stored!.State);
        Assert.Equal("oid-decider", stored.ApproverObjectId);
    }

    [Fact]
    public async Task An_approver_can_deny_from_the_screen()
    {
        var request = await SeedPendingAsync("oid-deny-me");
        using var approver = Client("oid-decider2", "Mina.Approver");

        var response = await PostDecisionAsync(approver, "/approvals/deny", request.Id, ttlMinutes: null);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var stored = await _factory.Requests.FindAsync(request.Id, default);
        Assert.Equal(SensitiveSessionState.Denied, stored!.State);
    }

    [Fact]
    public async Task Self_approval_is_refused_and_reported_on_the_screen()
    {
        // The requester also holds the approver role — the screen lets them try, the control plane
        // refuses, and the refusal comes back as a message rather than a decision.
        var request = await SeedPendingAsync("oid-self");
        using var self = Client("oid-self", "Mina.Analyst,Mina.Approver");

        var response = await PostDecisionAsync(self, "/approvals/approve", request.Id, 60);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Contains("error=", response.Headers.Location!.ToString(), StringComparison.Ordinal);

        var stored = await _factory.Requests.FindAsync(request.Id, default);
        Assert.Equal(SensitiveSessionState.Requested, stored!.State);
    }

    [Fact]
    public async Task A_decision_without_an_antiforgery_token_is_rejected()
    {
        var request = await SeedPendingAsync("oid-noxsrf");
        using var approver = Client("oid-decider3", "Mina.Approver");

        using var content = new FormUrlEncodedContent(
            [new KeyValuePair<string, string>("requestId", request.Id.ToString()),
             new KeyValuePair<string, string>("ttlMinutes", "60")]);
        var response = await approver.PostAsync(new Uri("/approvals/approve", UriKind.Relative), content);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var stored = await _factory.Requests.FindAsync(request.Id, default);
        Assert.Equal(SensitiveSessionState.Requested, stored!.State);
    }

    [Fact]
    public async Task The_sessions_screen_shows_the_logging_mode()
    {
        var request = await SeedPendingAsync("oid-mode");
        var session = await _factory.Sessions.FindAsync(request.SessionId, default);
        session!.MarkSensitive();
        await _factory.Sessions.UpdateAsync(session, default);

        var html = await Client("oid-viewer", "Mina.Approver").GetStringAsync(
            new Uri("/sessions", UriKind.Relative));

        Assert.Contains("Sensitive", html, StringComparison.Ordinal);
        Assert.Contains("oid-mode@fiaumalta.org", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_overview_counts_what_is_happening()
    {
        await SeedPendingAsync("oid-overview", "CASE-OVERVIEW");

        var html = await Client("oid-viewer2", "Mina.Approver").GetStringAsync(new Uri("/", UriKind.Relative));

        Assert.Contains("Awaiting approval", html, StringComparison.Ordinal);
        Assert.Contains("Active sessions", html, StringComparison.Ordinal);
        // francecentral is approved but has no active stamp, so it must not read as selectable.
        Assert.Contains("approved, no active stamp", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_approval_made_on_the_screen_reaches_the_audit_chain()
    {
        var request = await SeedPendingAsync("oid-audited-approval");
        using var approver = Client("oid-audit-decider", "Mina.Approver");

        var response = await PostDecisionAsync(approver, "/approvals/approve", request.Id, 45);
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);

        // An approval decided here must be as recorded as one decided over the API: the approver,
        // the request and the window it granted (ADR-0003).
        var events = await _factory.Audit.ReadRecentAsync(50, default);
        var approved = Assert.Single(events, e => e.EventType == "sensitive_approved"
            && e.SessionId == request.SessionId);

        Assert.Contains("oid-audit-decider@fiaumalta.org", approved.Data, StringComparison.Ordinal);
        Assert.Contains(request.Id.ToString(), approved.Data, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_denial_made_on_the_screen_reaches_the_audit_chain()
    {
        var request = await SeedPendingAsync("oid-audited-denial");
        using var approver = Client("oid-audit-denier", "Mina.Approver");

        await PostDecisionAsync(approver, "/approvals/deny", request.Id, ttlMinutes: null);

        var events = await _factory.Audit.ReadRecentAsync(50, default);
        Assert.Single(events, e => e.EventType == "sensitive_denied" && e.SessionId == request.SessionId);
    }

    [Fact]
    public async Task An_analyst_cannot_read_the_sessions_or_overview_screens()
    {
        await SeedPendingAsync("oid-crossuser");
        using var analyst = Client("oid-curious", "Mina.Analyst");

        // These screens name every analyst, their device, and who is under an approved suppression.
        foreach (var path in new[] { "/sessions", "/" })
        {
            var response = await analyst.GetAsync(new Uri(path, UriKind.Relative));
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            Assert.DoesNotContain(
                "oid-crossuser@fiaumalta.org",
                await response.Content.ReadAsStringAsync(),
                StringComparison.Ordinal);
        }
    }

    /// <summary>GETs the queue to obtain an antiforgery token and cookie, then posts the decision.</summary>
    private async Task<HttpResponseMessage> PostDecisionAsync(
        HttpClient client, string path, Guid requestId, int? ttlMinutes)
    {
        var page = await client.GetAsync(new Uri("/approvals", UriKind.Relative));
        var html = await page.Content.ReadAsStringAsync();
        var token = Regex.Match(html, """name="__RequestVerificationToken"[^>]*value="([^"]+)""").Groups[1].Value;
        Assert.False(string.IsNullOrEmpty(token), "No antiforgery token was rendered on the approvals form.");

        var fields = new List<KeyValuePair<string, string>>
        {
            new("__RequestVerificationToken", token),
            new("requestId", requestId.ToString()),
        };

        if (ttlMinutes is not null)
        {
            fields.Add(new KeyValuePair<string, string>("ttlMinutes", ttlMinutes.Value.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        }

        using var content = new FormUrlEncodedContent(fields);
        var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = content };
        foreach (var cookie in page.Headers.GetValues("Set-Cookie"))
        {
            request.Headers.Add("Cookie", cookie.Split(';')[0]);
        }

        return await client.SendAsync(request);
    }
}
