using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace Mina.ControlPlane.Api.Tests;

/// <summary>
/// The browsing-data review API (M3-8) as it behaves through the running application. Off-hours
/// computation, the query guardrail, and a suppressed session's structural refusal to expose
/// hostnames are already proven exhaustively at the service level
/// (<c>BrowsingDataReviewServiceTests</c>, including an adversarial stray-row case); this file's
/// job is the one thing only a real HTTP round trip through the real DI composition can prove --
/// that the wiring reaches the same audit chain and the same telemetry store the rest of the
/// application uses, not a path a unit test's fakes never exercise. <c>AuthorisationMatrixTests</c>
/// covers every wrong role being refused; this file is the positive case
/// <see cref="AuthorisationMatrixTests.PolicyGatedRoutes"/>'s own doc comment defers here.
/// </summary>
public sealed class BrowsingDataApiTests(MinaApiFactory factory) : IClassFixture<MinaApiFactory>
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

    private static string NewCsrPem()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var der = new CertificateRequest("CN=mina-agent", key, HashAlgorithmName.SHA256).CreateSigningRequest();
        return PemEncoding.WriteString("CERTIFICATE REQUEST", der);
    }

    private async Task<Guid> IssueSessionAsync(HttpClient analyst)
    {
        var issue = await analyst.PostAsJsonAsync(
            new Uri("/api/sessions", UriKind.Relative), new { region = "westeurope", csrPem = NewCsrPem() });
        issue.EnsureSuccessStatusCode();
        return JsonDocument.Parse(await issue.Content.ReadAsStringAsync()).RootElement.GetProperty("sessionId").GetGuid();
    }

    private Task<HttpResponseMessage> IngestHostnameAsync(Guid sessionId, string hostname, DateTimeOffset occurredAt) =>
        Client("oid-node-browsing", "Mina.Node,Mina.Node.westeurope").PostAsJsonAsync(
            new Uri("/api/nodes/telemetry", UriKind.Relative), new
            {
                region = "westeurope",
                items = new[]
                {
                    new { sessionId, occurredAt, hostname, port = 443, bytesUp = 100L, bytesDown = 2000L, durationMs = 250 },
                },
            });

    [Fact]
    public async Task A_telemetry_viewer_sees_the_hostname_a_node_actually_reported()
    {
        var analyst = Client("oid-browsing-a", "Mina.Analyst");
        var sessionId = await IssueSessionAsync(analyst);
        var occurredAt = DateTimeOffset.UtcNow.AddMinutes(-5);
        (await IngestHostnameAsync(sessionId, "real-target.example", occurredAt)).EnsureSuccessStatusCode();

        var viewer = Client("oid-browsing-viewer", "Mina.TelemetryViewer");
        var from = Uri.EscapeDataString(DateTimeOffset.UtcNow.AddDays(-1).ToString("O"));
        var to = Uri.EscapeDataString(DateTimeOffset.UtcNow.AddDays(1).ToString("O"));
        var response = await viewer.GetAsync(
            new Uri($"/api/browsing-data?analyst=oid-browsing-a&from={from}&to={to}", UriKind.Relative));
        response.EnsureSuccessStatusCode();

        var result = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
        var session = result.GetProperty("sessions").EnumerateArray()
            .Single(s => s.GetProperty("sessionId").GetGuid() == sessionId);
        var hostnames = session.GetProperty("hostnames").EnumerateArray().ToList();

        Assert.Single(hostnames);
        Assert.Equal("real-target.example", hostnames[0].GetProperty("hostname").GetString());
        Assert.Equal(443, hostnames[0].GetProperty("port").GetInt32());
        Assert.Equal(2000, hostnames[0].GetProperty("bytesDown").GetInt64());
        // isOffHours is present in the shape; MinaApiFactory leaves Mina:ManagementUi:OfficeHours
        // unset, so its value here is "flagging is off", not a claim about this specific timestamp
        // -- that claim is BrowsingDataReviewServiceTests' job, not this file's.
        Assert.True(hostnames[0].TryGetProperty("isOffHours", out _));
    }

    [Fact]
    public async Task Reviewing_browsing_data_lands_in_the_audit_chain_with_no_hostname_in_it()
    {
        var analyst = Client("oid-browsing-b", "Mina.Analyst");
        var sessionId = await IssueSessionAsync(analyst);
        const string secretHostname = "audit-must-not-see-this.example";
        (await IngestHostnameAsync(sessionId, secretHostname, DateTimeOffset.UtcNow.AddMinutes(-1)))
            .EnsureSuccessStatusCode();

        var viewer = Client("oid-browsing-viewer-2", "Mina.TelemetryViewer");
        var from = Uri.EscapeDataString(DateTimeOffset.UtcNow.AddDays(-1).ToString("O"));
        var to = Uri.EscapeDataString(DateTimeOffset.UtcNow.AddDays(1).ToString("O"));
        (await viewer.GetAsync(new Uri($"/api/browsing-data?analyst=oid-browsing-b&from={from}&to={to}", UriKind.Relative)))
            .EnsureSuccessStatusCode();

        var recent = await Client("oid-admin-browsing", "Mina.Admin")
            .GetAsync(new Uri("/api/audit/recent?limit=200", UriKind.Relative));
        recent.EnsureSuccessStatusCode();
        var events = JsonDocument.Parse(await recent.Content.ReadAsStringAsync()).RootElement;

        var viewedEvents = events.EnumerateArray()
            .Where(e => e.GetProperty("eventType").GetString() == "telemetry_viewed"
                        && e.GetProperty("userPrincipalName").GetString() == "oid-browsing-viewer-2@example.org")
            .ToList();
        Assert.NotEmpty(viewedEvents);

        // Same content-scan discipline as AuditApiTests.No_audit_event_carries_a_hostname, applied
        // to this endpoint specifically: the audit trail proves *that* C3 was read, never *what*.
        var allPayloads = string.Join(' ', events.EnumerateArray().Select(e => e.GetProperty("data").GetString()));
        Assert.DoesNotContain(secretHostname, allPayloads, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_backwards_date_range_is_refused_with_a_client_error_not_a_500()
    {
        var viewer = Client("oid-browsing-viewer-3", "Mina.TelemetryViewer");
        var from = Uri.EscapeDataString(DateTimeOffset.UtcNow.ToString("O"));
        var to = Uri.EscapeDataString(DateTimeOffset.UtcNow.AddDays(-1).ToString("O"));

        var response = await viewer.GetAsync(
            new Uri($"/api/browsing-data?analyst=whoever&from={from}&to={to}", UriKind.Relative));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task An_unscoped_query_wider_than_the_guardrail_is_refused()
    {
        var viewer = Client("oid-browsing-viewer-4", "Mina.TelemetryViewer");
        var from = Uri.EscapeDataString(DateTimeOffset.UtcNow.AddDays(-200).ToString("O"));
        var to = Uri.EscapeDataString(DateTimeOffset.UtcNow.ToString("O"));

        // No 'analyst' query parameter at all: every analyst, and 200 days exceeds
        // BrowsingDataReviewService.MaxUnscopedRangeDays (90).
        var response = await viewer.GetAsync(new Uri($"/api/browsing-data?from={from}&to={to}", UriKind.Relative));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task The_analyst_picker_lists_someone_who_actually_has_a_session()
    {
        var analyst = Client("oid-browsing-picker", "Mina.Analyst");
        await IssueSessionAsync(analyst);

        var viewer = Client("oid-browsing-viewer-5", "Mina.TelemetryViewer");
        var response = await viewer.GetAsync(new Uri("/api/browsing-data/analysts", UriKind.Relative));
        response.EnsureSuccessStatusCode();

        var analysts = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
        Assert.Contains(
            analysts.EnumerateArray(),
            a => a.GetProperty("userObjectId").GetString() == "oid-browsing-picker");
    }
}
