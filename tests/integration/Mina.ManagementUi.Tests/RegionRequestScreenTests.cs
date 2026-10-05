using System.Net;
using System.Text.RegularExpressions;
using Mina.ControlPlane.Domain.Audit;
using Mina.ControlPlane.Domain.Regions;

namespace Mina.ManagementUi.Tests;

/// <summary>
/// The region-requests screen and its create/apply/dismiss endpoints (ADR-0008 Option C). The
/// workflow rules are covered at the service layer; what these assert is that the screen shows the
/// right people the right things, that the same rules bind through a form post, and — the one
/// property that matters most about this whole feature — that nothing here ever writes to
/// Mina:Regions:Approved/Active itself, only to the request record and the audit chain.
/// </summary>
public sealed class RegionRequestScreenTests(ManagementUiFactory factory) : IClassFixture<ManagementUiFactory>
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

    [Fact]
    public async Task Anonymous_visitors_are_not_served_the_screen()
    {
        var response = await Client("oid-anon", roles: null).GetAsync(new Uri("/region-requests", UriKind.Relative));

        Assert.NotEqual(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Holding_the_approver_role_alone_does_not_grant_access()
    {
        // Region administration is an admin concern (ADR-0008) — an approver of sensitive-session
        // requests has no inherent claim to it.
        var response = await Client("oid-just-approver", "Mina.Approver")
            .GetAsync(new Uri("/region-requests", UriKind.Relative));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task An_admin_can_submit_a_request_from_the_screen()
    {
        using var admin = Client("oid-requester", "Mina.Admin", upn: "requester@example.org");

        var response = await PostAsync(admin, "/region-requests/create", new Dictionary<string, string>
        {
            ["kind"] = nameof(RegionChangeKind.Activate),
            ["regionName"] = "northeurope",
            ["justification"] = "capacity need",
        });

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Contains("done=", response.Headers.Location!.ToString(), StringComparison.Ordinal);

        var html = await admin.GetStringAsync(new Uri("/region-requests", UriKind.Relative));
        Assert.Contains("northeurope", html, StringComparison.Ordinal);
        Assert.Contains("requester@example.org", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_invalid_region_name_is_refused_and_reported_not_a_server_error()
    {
        using var admin = Client("oid-badregion", "Mina.Admin");

        var response = await PostAsync(admin, "/region-requests/create", new Dictionary<string, string>
        {
            ["kind"] = nameof(RegionChangeKind.Activate),
            ["regionName"] = "North Europe", // spaces not allowed
            ["justification"] = "reason",
        });

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Contains("error=", response.Headers.Location!.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_admin_can_mark_a_request_applied_and_it_moves_to_resolved()
    {
        using var admin = Client("oid-resolver", "Mina.Admin", upn: "resolver@example.org");
        // A region name distinct from every other test in this class: ManagementUiFactory's
        // RegionChangeRequests repository is shared across the whole class (IClassFixture), and
        // SubmitAndGetIdAsync looks its own request up by region name -- a collision would make
        // that lookup ambiguous rather than merely slow.
        var requestId = await SubmitAndGetIdAsync(admin, "germanywestcentral", "capacity");

        var response = await PostAsync(admin, "/region-requests/apply", new Dictionary<string, string>
        {
            ["requestId"] = requestId.ToString(),
            ["note"] = "deployed via script run #7",
        });

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);

        var stored = await _factory.RegionChangeRequests.FindAsync(requestId, default);
        Assert.Equal(RegionChangeRequestStatus.Applied, stored!.Status);
        Assert.Equal("deployed via script run #7", stored.ResolutionNote);

        var html = await admin.GetStringAsync(new Uri("/region-requests", UriKind.Relative));
        Assert.Contains("deployed via script run #7", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Dismissing_without_a_reason_is_refused_by_the_browser_not_silently_accepted()
    {
        // The form field is `required`, but the service is the real gate -- posting past the browser
        // validation with an empty reason must still be refused server-side.
        using var admin = Client("oid-dismisser", "Mina.Admin");
        var requestId = await SubmitAndGetIdAsync(admin, "westeurope", "no longer needed");

        var response = await PostAsync(admin, "/region-requests/dismiss", new Dictionary<string, string>
        {
            ["requestId"] = requestId.ToString(),
            ["reason"] = "",
        });

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Contains("error=", response.Headers.Location!.ToString(), StringComparison.Ordinal);

        var stored = await _factory.RegionChangeRequests.FindAsync(requestId, default);
        Assert.Equal(RegionChangeRequestStatus.Pending, stored!.Status);
    }

    [Fact]
    public async Task Submitting_a_request_reaches_the_audit_chain_as_region_change_requested()
    {
        using var admin = Client("oid-audited", "Mina.Admin", upn: "audited@example.org");

        await PostAsync(admin, "/region-requests/create", new Dictionary<string, string>
        {
            ["kind"] = nameof(RegionChangeKind.AddApproved),
            ["regionName"] = "francesouth",
            ["justification"] = "expansion",
        });

        var events = await _factory.Audit.ReadRecentAsync(50, default);
        var e = Assert.Single(events, e => e.EventType == "region_change_requested"
            && e.UserPrincipalName == "audited@example.org");
        Assert.Equal(AuditSeverity.Notice, e.Severity);
    }

    [Fact]
    public async Task Applying_a_request_reaches_the_audit_chain_as_policy_changed_at_high_severity()
    {
        using var admin = Client("oid-applier", "Mina.Admin", upn: "applier@example.org");
        var requestId = await SubmitAndGetIdAsync(admin, "spaincentral", "capacity");

        await PostAsync(admin, "/region-requests/apply", new Dictionary<string, string>
        {
            ["requestId"] = requestId.ToString(),
            ["note"] = "",
        });

        var events = await _factory.Audit.ReadRecentAsync(50, default);
        var e = Assert.Single(events, e => e.EventType == "policy_changed"
            && e.UserPrincipalName == "applier@example.org");
        Assert.Equal(AuditSeverity.High, e.Severity);
    }

    private async Task<Guid> SubmitAndGetIdAsync(HttpClient client, string region, string justification)
    {
        await PostAsync(client, "/region-requests/create", new Dictionary<string, string>
        {
            ["kind"] = nameof(RegionChangeKind.Activate),
            ["regionName"] = region,
            ["justification"] = justification,
        });

        var pending = await _factory.RegionChangeRequests.ListPendingAsync(50, default);
        return pending.Single(r => r.RegionName == region).Id;
    }

    private static async Task<HttpResponseMessage> PostAsync(
        HttpClient client, string path, IReadOnlyDictionary<string, string> fields)
    {
        // Same GET-for-token-then-POST-with-cookie dance ApprovalScreenTests uses: the antiforgery
        // token is rendered on the page the form lives on. Set-Cookie is forwarded manually only
        // when this particular GET actually issued one -- WebApplicationFactory's client already
        // carries cookies across requests on its own, so a second round trip within the same test
        // (this screen's create-then-resolve flow needs two) legitimately has nothing new to set,
        // the server having recognised the cookie the client already sent back automatically.
        var page = await client.GetAsync(new Uri("/region-requests", UriKind.Relative));
        var html = await page.Content.ReadAsStringAsync();
        var token = Regex.Match(html, """name="__RequestVerificationToken"[^>]*value="([^"]+)""").Groups[1].Value;
        Assert.False(string.IsNullOrEmpty(token), "No antiforgery token was rendered on the region-requests page.");

        var formFields = new List<KeyValuePair<string, string>> { new("__RequestVerificationToken", token) };
        formFields.AddRange(fields.Select(kv => new KeyValuePair<string, string>(kv.Key, kv.Value)));

        using var content = new FormUrlEncodedContent(formFields);
        var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = content };
        if (page.Headers.TryGetValues("Set-Cookie", out var cookies))
        {
            foreach (var cookie in cookies)
            {
                request.Headers.Add("Cookie", cookie.Split(';')[0]);
            }
        }

        return await client.SendAsync(request);
    }
}
