using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace Mina.ControlPlane.Api.Tests;

/// <summary>
/// The egress-node interface: only nodes may read the session allowlist or post telemetry, and the
/// control plane's own view of suppression decides what is recorded — not the node's.
/// </summary>
public sealed class NodeApiTests(MinaApiFactory factory) : IClassFixture<MinaApiFactory>
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

    private async Task<Guid> NewSessionAsync(HttpClient analyst)
    {
        var response = await analyst.PostAsJsonAsync(
            new Uri("/api/sessions", UriKind.Relative), new { region = "westeurope", csrPem = NewCsrPem() });
        response.EnsureSuccessStatusCode();
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync())
            .RootElement.GetProperty("sessionId").GetGuid();
    }

    private async Task<HttpResponseMessage> PostTelemetryAsync(
        HttpClient node, Guid sessionId, string? hostname) =>
        await node.PostAsJsonAsync(new Uri("/api/nodes/telemetry", UriKind.Relative), new
        {
            region = "westeurope",
            items = new[]
            {
                new
                {
                    sessionId,
                    occurredAt = DateTimeOffset.UtcNow,
                    hostname,
                    port = 443,
                    bytesUp = 100L,
                    bytesDown = 900L,
                    durationMs = 42,
                },
            },
        });

    [Fact]
    public async Task An_analyst_cannot_read_the_node_allowlist()
    {
        var response = await Client("oid-a", "Mina.Analyst").GetAsync(
            new Uri("/api/nodes/westeurope/sessions", UriKind.Relative));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task An_analyst_cannot_post_telemetry()
    {
        var analyst = Client("oid-b", "Mina.Analyst");
        var sessionId = await NewSessionAsync(analyst);

        var response = await PostTelemetryAsync(analyst, sessionId, "example.org");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Anonymous_callers_cannot_reach_the_node_interface()
    {
        var response = await _factory.CreateClient().GetAsync(
            new Uri("/api/nodes/westeurope/sessions", UriKind.Relative));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task A_node_sees_active_sessions_for_its_region_with_their_suppression_state()
    {
        var analyst = Client("oid-allowlist", "Mina.Analyst");
        var sessionId = await NewSessionAsync(analyst);

        var response = await Client("oid-node", "Mina.Node").GetAsync(
            new Uri("/api/nodes/westeurope/sessions", UriKind.Relative));
        response.EnsureSuccessStatusCode();

        var entries = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
        var mine = entries.EnumerateArray().Single(e => e.GetProperty("sessionId").GetGuid() == sessionId);
        Assert.False(mine.GetProperty("suppressed").GetBoolean());
    }

    [Fact]
    public async Task A_node_reads_no_sessions_for_a_region_with_none()
    {
        var response = await Client("oid-node2", "Mina.Node").GetAsync(
            new Uri("/api/nodes/northeurope/sessions", UriKind.Relative));
        response.EnsureSuccessStatusCode();

        var entries = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal(0, entries.GetArrayLength());
    }

    [Fact]
    public async Task Telemetry_for_a_normal_session_is_recorded()
    {
        var analyst = Client("oid-record", "Mina.Analyst");
        var sessionId = await NewSessionAsync(analyst);

        var response = await PostTelemetryAsync(Client("oid-node3", "Mina.Node"), sessionId, "example.org");
        response.EnsureSuccessStatusCode();

        var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal(1, body.GetProperty("recorded").GetInt32());
        Assert.Equal(0, body.GetProperty("suppressionMismatches").GetInt32());
    }

    [Fact]
    public async Task Once_suppressed_the_allowlist_says_so_and_hostnames_stop_being_recorded()
    {
        var analyst = Client("oid-suppressed", "Mina.Analyst");
        var approver = Client("oid-manager-t", "Mina.Approver");
        var node = Client("oid-node4", "Mina.Node");
        var sessionId = await NewSessionAsync(analyst);

        // Request → approve → activate, exactly as the workflow requires.
        var created = await analyst.PostAsJsonAsync(
            new Uri($"/api/sessions/{sessionId}/sensitive", UriKind.Relative),
            new { justificationReference = "CASE-TELEMETRY", requestedMinutes = 60 });
        var requestId = JsonDocument.Parse(await created.Content.ReadAsStringAsync())
            .RootElement.GetProperty("requestId").GetGuid();
        await approver.PostAsJsonAsync(
            new Uri($"/api/sensitive-requests/{requestId}/approve", UriKind.Relative), new { ttlMinutes = 60 });
        var activated = await approver.PostAsync(
            new Uri($"/api/sensitive-requests/{requestId}/activate", UriKind.Relative), content: null);
        Assert.Equal(HttpStatusCode.Forbidden, activated.StatusCode); // only the requester activates
        await analyst.PostAsync(new Uri($"/api/sensitive-requests/{requestId}/activate", UriKind.Relative), null);

        // The node is now told to withhold destinations for this session.
        var allowlist = await node.GetAsync(new Uri("/api/nodes/westeurope/sessions", UriKind.Relative));
        var entry = JsonDocument.Parse(await allowlist.Content.ReadAsStringAsync()).RootElement
            .EnumerateArray().Single(e => e.GetProperty("sessionId").GetGuid() == sessionId);
        Assert.True(entry.GetProperty("suppressed").GetBoolean());

        // And if it sends one anyway, the control plane discards it and flags the discrepancy.
        var response = await PostTelemetryAsync(node, sessionId, "should-not-be-recorded.example");
        response.EnsureSuccessStatusCode();
        var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;

        Assert.Equal(0, body.GetProperty("recorded").GetInt32());
        Assert.Equal(1, body.GetProperty("suppressionMismatches").GetInt32());
        Assert.Equal(1, body.GetProperty("aggregated").GetInt32());
    }

    [Fact]
    public async Task Telemetry_for_an_unknown_session_is_reported_as_unattributable()
    {
        var response = await PostTelemetryAsync(Client("oid-node5", "Mina.Node"), Guid.NewGuid(), "orphan.example");
        response.EnsureSuccessStatusCode();

        var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal(1, body.GetProperty("unattributable").GetInt32());
        Assert.Equal(0, body.GetProperty("recorded").GetInt32());
    }

    [Fact]
    public async Task A_batch_without_a_region_is_a_bad_request()
    {
        var response = await Client("oid-node6", "Mina.Node").PostAsJsonAsync(
            new Uri("/api/nodes/telemetry", UriKind.Relative),
            new { region = "", items = Array.Empty<object>() });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }
}
