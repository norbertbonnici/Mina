using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace Mina.ControlPlane.Api.Tests;

/// <summary>
/// The audit trail as it behaves through the running application: governance actions land in the
/// chain, the chain verifies, and only administrators can read or verify it.
/// </summary>
public sealed class AuditApiTests(MinaApiFactory factory) : IClassFixture<MinaApiFactory>
{
    private readonly MinaApiFactory _factory = factory;

    private HttpClient Client(string oid, string roles)
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Test-Oid", oid);
        client.DefaultRequestHeaders.Add("X-Test-Upn", $"{oid}@fiaumalta.org");
        client.DefaultRequestHeaders.Add("X-Test-Device", "device-1");
        client.DefaultRequestHeaders.Add("X-Test-Roles", roles);
        return client;
    }

    private static string NewCsrPem()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var der = new CertificateRequest("CN=mina-agent", key, HashAlgorithmName.SHA256).CreateSigningRequest();
        return PemEncoding.WriteString("CERTIFICATE REQUEST", der);
    }

    private async Task<JsonElement> RecentAsync()
    {
        var response = await Client("oid-admin", "Mina.Admin").GetAsync(
            new Uri("/api/audit/recent?limit=200", UriKind.Relative));
        response.EnsureSuccessStatusCode();
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement.Clone();
    }

    [Fact]
    public async Task Only_administrators_can_read_the_trail()
    {
        foreach (var roles in new[] { "Mina.Analyst", "Mina.Approver", "Mina.Node" })
        {
            var response = await Client($"oid-{roles}", roles).GetAsync(
                new Uri("/api/audit/recent", UriKind.Relative));
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        }

        var anonymous = await _factory.CreateClient().GetAsync(new Uri("/api/audit/recent", UriKind.Relative));
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
    }

    [Fact]
    public async Task Starting_a_session_lands_in_the_audit_chain()
    {
        var analyst = Client("oid-audited", "Mina.Analyst");
        var issue = await analyst.PostAsJsonAsync(
            new Uri("/api/sessions", UriKind.Relative), new { region = "westeurope", csrPem = NewCsrPem() });
        issue.EnsureSuccessStatusCode();
        var sessionId = JsonDocument.Parse(await issue.Content.ReadAsStringAsync())
            .RootElement.GetProperty("sessionId").GetGuid();

        var events = await RecentAsync();
        var started = events.EnumerateArray().Single(e =>
            e.GetProperty("eventType").GetString() == "session_started"
            && e.GetProperty("sessionId").GetGuid() == sessionId);

        Assert.Equal("Info", started.GetProperty("severity").GetString());
        Assert.Equal("westeurope", started.GetProperty("region").GetString());
        Assert.Equal("oid-audited@fiaumalta.org", started.GetProperty("userPrincipalName").GetString());
    }

    [Fact]
    public async Task A_refused_request_is_audited_too()
    {
        // francecentral is approved but has no active stamp, so this is denied.
        var analyst = Client("oid-refused", "Mina.Analyst");
        await analyst.PostAsJsonAsync(
            new Uri("/api/sessions", UriKind.Relative), new { region = "francecentral", csrPem = NewCsrPem() });

        var events = await RecentAsync();
        var denied = events.EnumerateArray().Where(e =>
            e.GetProperty("eventType").GetString() == "authz_denied"
            && e.GetProperty("userPrincipalName").GetString() == "oid-refused@fiaumalta.org").ToList();

        Assert.NotEmpty(denied);
        Assert.Equal("Warning", denied[0].GetProperty("severity").GetString());
    }

    [Fact]
    public async Task The_suppression_decision_trail_is_recorded_end_to_end()
    {
        var analyst = Client("oid-trail", "Mina.Analyst");
        var approver = Client("oid-trail-mgr", "Mina.Approver");

        var issue = await analyst.PostAsJsonAsync(
            new Uri("/api/sessions", UriKind.Relative), new { region = "westeurope", csrPem = NewCsrPem() });
        var sessionId = JsonDocument.Parse(await issue.Content.ReadAsStringAsync())
            .RootElement.GetProperty("sessionId").GetGuid();

        var created = await analyst.PostAsJsonAsync(
            new Uri($"/api/sessions/{sessionId}/sensitive", UriKind.Relative),
            new { justificationReference = "CASE-AUDIT", requestedMinutes = 60 });
        var requestId = JsonDocument.Parse(await created.Content.ReadAsStringAsync())
            .RootElement.GetProperty("requestId").GetGuid();

        await approver.PostAsJsonAsync(
            new Uri($"/api/sensitive-requests/{requestId}/approve", UriKind.Relative), new { ttlMinutes = 30 });
        await analyst.PostAsync(new Uri($"/api/sensitive-requests/{requestId}/activate", UriKind.Relative), null);

        var events = await RecentAsync();
        var forSession = events.EnumerateArray()
            .Where(e => e.TryGetProperty("sessionId", out var s)
                        && s.ValueKind == JsonValueKind.String && s.GetGuid() == sessionId)
            .Select(e => e.GetProperty("eventType").GetString())
            .ToList();

        // Who asked, who decided and when it became active are all in the trail — the events that
        // must survive suppression itself (ADR-0003).
        Assert.Contains("sensitive_requested", forSession);
        Assert.Contains("sensitive_approved", forSession);
        Assert.Contains("sensitive_activated", forSession);

        var approved = events.EnumerateArray().Single(e =>
            e.GetProperty("eventType").GetString() == "sensitive_approved"
            && e.GetProperty("sessionId").GetGuid() == sessionId);
        Assert.Contains("oid-trail-mgr@fiaumalta.org", approved.GetProperty("data").GetString()!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task No_audit_event_carries_a_hostname()
    {
        var analyst = Client("oid-nohost", "Mina.Analyst");
        var issue = await analyst.PostAsJsonAsync(
            new Uri("/api/sessions", UriKind.Relative), new { region = "westeurope", csrPem = NewCsrPem() });
        var sessionId = JsonDocument.Parse(await issue.Content.ReadAsStringAsync())
            .RootElement.GetProperty("sessionId").GetGuid();

        await Client("oid-node-a", "Mina.Node").PostAsJsonAsync(
            new Uri("/api/nodes/telemetry", UriKind.Relative), new
            {
                region = "westeurope",
                items = new[]
                {
                    new { sessionId, occurredAt = DateTimeOffset.UtcNow, hostname = "secret-target.example",
                          port = 443, bytesUp = 1L, bytesDown = 1L, durationMs = 1 },
                },
            });

        var events = await RecentAsync();
        var payloads = string.Join(' ', events.EnumerateArray().Select(e => e.GetProperty("data").GetString()));

        // The audit trail records that things happened, not where anyone browsed: destinations
        // belong to the telemetry data class, which has its own access controls.
        Assert.DoesNotContain("secret-target.example", payloads, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_chain_verifies_after_real_activity()
    {
        var analyst = Client("oid-verify", "Mina.Analyst");
        for (var i = 0; i < 3; i++)
        {
            await analyst.PostAsJsonAsync(
                new Uri("/api/sessions", UriKind.Relative), new { region = "westeurope", csrPem = NewCsrPem() });
        }

        var response = await Client("oid-admin2", "Mina.Admin").GetAsync(
            new Uri("/api/audit/verify", UriKind.Relative));
        response.EnsureSuccessStatusCode();
        var result = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;

        Assert.True(result.GetProperty("intact").GetBoolean());
        Assert.True(result.GetProperty("verified").GetInt64() > 0);
        Assert.Equal(JsonValueKind.Null, result.GetProperty("brokenAtSequence").ValueKind);
    }
}
