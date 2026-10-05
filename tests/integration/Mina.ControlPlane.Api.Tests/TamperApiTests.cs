using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace Mina.ControlPlane.Api.Tests;

/// <summary>
/// The endpoint agent's tamper self-monitoring (ARCHITECTURE §3.1 point 5), as it lands in the
/// audit trail — `client_tamper_suspected` (EVENT_SCHEMAS §3).
/// </summary>
public sealed class TamperApiTests(MinaApiFactory factory) : IClassFixture<MinaApiFactory>
{
    private readonly MinaApiFactory _factory = factory;

    private HttpClient Client(string oid, string roles)
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Test-Oid", oid);
        client.DefaultRequestHeaders.Add("X-Test-Upn", $"{oid}@example.org");
        client.DefaultRequestHeaders.Add("X-Test-Device", "device-1");
        client.DefaultRequestHeaders.Add("X-Test-Roles", roles);
        return client;
    }

    private async Task<JsonElement> RecentAsync()
    {
        var response = await Client("oid-admin-tamper", "Mina.Admin").GetAsync(
            new Uri("/api/audit/recent?limit=200", UriKind.Relative));
        response.EnsureSuccessStatusCode();
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement.Clone();
    }

    [Fact]
    public async Task A_known_indicator_is_accepted_and_lands_in_the_audit_chain_as_high_severity()
    {
        var analyst = Client("oid-tampered", "Mina.Analyst");

        var response = await analyst.PostAsJsonAsync(
            new Uri("/api/agent/tamper-events", UriKind.Relative), new { indicator = "wfp_rule_missing" });

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);

        var events = await RecentAsync();
        var recorded = events.EnumerateArray().Single(e =>
            e.GetProperty("eventType").GetString() == "client_tamper_suspected"
            && e.GetProperty("userPrincipalName").GetString() == "oid-tampered@example.org");

        Assert.Equal("High", recorded.GetProperty("severity").GetString());
        Assert.Equal("EndpointAgent", recorded.GetProperty("component").GetString());
        Assert.Contains("wfp_rule_missing", recorded.GetProperty("data").GetString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("unmanaged_browser_instance")]
    [InlineData("foreign_proxy_client")]
    [InlineData("flag_mismatch")]
    public async Task Every_documented_indicator_is_accepted(string indicator)
    {
        var analyst = Client($"oid-{indicator}", "Mina.Analyst");

        var response = await analyst.PostAsJsonAsync(
            new Uri("/api/agent/tamper-events", UriKind.Relative), new { indicator });

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
    }

    [Fact]
    public async Task An_unknown_indicator_is_refused_rather_than_recorded()
    {
        var analyst = Client("oid-bad-indicator", "Mina.Analyst");

        var response = await analyst.PostAsJsonAsync(
            new Uri("/api/agent/tamper-events", UriKind.Relative), new { indicator = "totally_made_up" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        var events = await RecentAsync();
        Assert.DoesNotContain(events.EnumerateArray(), e =>
            e.GetProperty("eventType").GetString() == "client_tamper_suspected"
            && e.GetProperty("userPrincipalName").GetString() == "oid-bad-indicator@example.org");
    }

    [Fact]
    public async Task The_session_id_is_recorded_when_the_agent_has_one()
    {
        var analyst = Client("oid-tamper-session", "Mina.Analyst");
        var sessionId = Guid.NewGuid();

        await analyst.PostAsJsonAsync(
            new Uri("/api/agent/tamper-events", UriKind.Relative),
            new { indicator = "foreign_proxy_client", sessionId });

        var events = await RecentAsync();
        var recorded = events.EnumerateArray().Single(e =>
            e.GetProperty("eventType").GetString() == "client_tamper_suspected"
            && e.GetProperty("userPrincipalName").GetString() == "oid-tamper-session@example.org");

        Assert.Equal(sessionId, recorded.GetProperty("sessionId").GetGuid());
    }

    [Fact]
    public async Task Only_an_analyst_can_report_tamper_indicators()
    {
        foreach (var roles in new[] { "Mina.Approver", "Mina.Admin", "Mina.Node" })
        {
            var response = await Client($"oid-wrong-role-{roles}", roles).PostAsJsonAsync(
                new Uri("/api/agent/tamper-events", UriKind.Relative), new { indicator = "wfp_rule_missing" });
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        }

        var anonymous = await _factory.CreateClient().PostAsJsonAsync(
            new Uri("/api/agent/tamper-events", UriKind.Relative), new { indicator = "wfp_rule_missing" });
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
    }
}
