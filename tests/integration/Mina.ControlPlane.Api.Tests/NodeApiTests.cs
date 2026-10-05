using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Mina.ControlPlane.Domain.Sessions;
using Mina.ControlPlane.Persistence;

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

        var response = await Client("oid-node", "Mina.Node,Mina.Node.westeurope").GetAsync(
            new Uri("/api/nodes/westeurope/sessions", UriKind.Relative));
        response.EnsureSuccessStatusCode();

        var entries = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
        var mine = entries.EnumerateArray().Single(e => e.GetProperty("sessionId").GetGuid() == sessionId);
        Assert.False(mine.GetProperty("suppressed").GetBoolean());
    }

    [Fact]
    public async Task A_node_reads_no_sessions_for_a_region_with_none()
    {
        var response = await Client("oid-node2", "Mina.Node,Mina.Node.northeurope").GetAsync(
            new Uri("/api/nodes/northeurope/sessions", UriKind.Relative));
        response.EnsureSuccessStatusCode();

        var entries = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal(0, entries.GetArrayLength());
    }

    [Fact]
    public async Task A_node_cannot_read_the_allowlist_of_a_region_it_was_not_granted()
    {
        // Holding the node role says the caller is a node; it does not say which one.
        var response = await Client("oid-node-weu", "Mina.Node,Mina.Node.westeurope").GetAsync(
            new Uri("/api/nodes/northeurope/sessions", UriKind.Relative));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task A_node_with_no_region_grant_is_entitled_to_nothing()
    {
        var response = await Client("oid-node-bare", "Mina.Node").GetAsync(
            new Uri("/api/nodes/westeurope/sessions", UriKind.Relative));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task A_node_cannot_post_telemetry_for_a_region_it_was_not_granted()
    {
        var analyst = Client("oid-crossregion", "Mina.Analyst");
        var sessionId = await NewSessionAsync(analyst);

        var response = await PostTelemetryAsync(
            Client("oid-node-neu", "Mina.Node,Mina.Node.northeurope"), sessionId, "example.org");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task A_session_issued_for_another_region_is_neither_listed_to_this_regions_node_nor_attributable_by_it()
    {
        // M2-6, THREAT_MODEL B4: the SAN-versus-claimed-region case end to end. The session is real
        // and live, but belongs to francecentral (approved, no active stamp). A westeurope node must not learn it exists from the
        // allowlist, and telemetry it claims for that session under its own region must be refused
        // as unattributable and audited as a region mismatch — not recorded against the analyst.
        // Seeded directly: the test configuration has no active francecentral stamp to issue through, and northeurope is left empty for the test that asserts an empty allowlist.
        var sessions = _factory.Services.GetRequiredService<InMemorySessionRepository>();
        var foreign = ResearchSession.Issue(
            Guid.NewGuid(), "oid-frc-analyst", "frc-analyst@example.org", "device-frc", "francecentral",
            DateTimeOffset.UtcNow, TimeSpan.FromHours(1), "serial-frc");
        await sessions.AddAsync(foreign, CancellationToken.None);

        var node = Client("oid-node-weu-foreign", "Mina.Node,Mina.Node.westeurope");

        var allowlist = await node.GetAsync(new Uri("/api/nodes/westeurope/sessions", UriKind.Relative));
        allowlist.EnsureSuccessStatusCode();
        var listed = JsonDocument.Parse(await allowlist.Content.ReadAsStringAsync()).RootElement;
        Assert.DoesNotContain(listed.EnumerateArray(), e => e.GetProperty("sessionId").GetGuid() == foreign.Id);

        var response = await PostTelemetryAsync(node, foreign.Id, "cross-region.example");
        response.EnsureSuccessStatusCode();
        var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal(0, body.GetProperty("recorded").GetInt32());
        Assert.Equal(1, body.GetProperty("unattributable").GetInt32());

        var audit = await Client("oid-admin-foreign", "Mina.Admin")
            .GetAsync(new Uri("/api/audit/recent?limit=200", UriKind.Relative));
        audit.EnsureSuccessStatusCode();
        var events = JsonDocument.Parse(await audit.Content.ReadAsStringAsync()).RootElement;
        Assert.Contains(events.EnumerateArray(), e =>
            e.GetProperty("eventType").GetString() == "telemetry_region_mismatch"
            && e.GetRawText().Contains(foreign.Id.ToString(), StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Telemetry_for_a_normal_session_is_recorded()
    {
        var analyst = Client("oid-record", "Mina.Analyst");
        var sessionId = await NewSessionAsync(analyst);

        var response = await PostTelemetryAsync(Client("oid-node3", "Mina.Node,Mina.Node.westeurope"), sessionId, "example.org");
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
        var node = Client("oid-node4", "Mina.Node,Mina.Node.westeurope");
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
        var response = await PostTelemetryAsync(Client("oid-node5", "Mina.Node,Mina.Node.westeurope"), Guid.NewGuid(), "orphan.example");
        response.EnsureSuccessStatusCode();

        var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal(1, body.GetProperty("unattributable").GetInt32());
        Assert.Equal(0, body.GetProperty("recorded").GetInt32());
    }

    [Fact]
    public async Task A_batch_without_a_region_is_a_bad_request()
    {
        var response = await Client("oid-node6", "Mina.Node,Mina.Node.westeurope").PostAsJsonAsync(
            new Uri("/api/nodes/telemetry", UriKind.Relative),
            new { region = "", items = Array.Empty<object>() });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    private static async Task<HttpResponseMessage> RequestCertificateAsync(
        HttpClient node, string region, byte[]? csrDer = null)
    {
        using var content = new ByteArrayContent(csrDer ?? NewCsrDer());
        content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
        return await node.PostAsync(new Uri($"/api/nodes/{region}/certificate", UriKind.Relative), content);
    }

    private static byte[] NewCsrDer()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return new CertificateRequest("CN=mina-node", key, HashAlgorithmName.SHA256).CreateSigningRequest();
    }

    [Fact]
    public async Task An_analyst_cannot_request_a_node_certificate()
    {
        var response = await RequestCertificateAsync(Client("oid-cert-analyst", "Mina.Analyst"), "westeurope");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Anonymous_callers_cannot_request_a_node_certificate()
    {
        using var content = new ByteArrayContent(NewCsrDer());
        var response = await _factory.CreateClient().PostAsync(
            new Uri("/api/nodes/westeurope/certificate", UriKind.Relative), content);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task A_node_cannot_request_a_certificate_for_a_region_it_was_not_granted()
    {
        var response = await RequestCertificateAsync(
            Client("oid-cert-wrongregion", "Mina.Node,Mina.Node.westeurope"), "northeurope");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task A_region_with_no_configured_egress_ingress_refuses_the_certificate_request()
    {
        // northeurope is approved (AC-008) but has no Mina:Egress:Regions entry in test config --
        // there is no ServerName to put in the SAN, so there is nothing safe to sign.
        var response = await RequestCertificateAsync(
            Client("oid-cert-noegress", "Mina.Node,Mina.Node.northeurope"), "northeurope");

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
    }

    [Fact]
    public async Task An_empty_request_body_is_a_bad_request()
    {
        var response = await RequestCertificateAsync(
            Client("oid-cert-empty", "Mina.Node,Mina.Node.westeurope"), "westeurope", csrDer: []);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task A_tampered_csr_is_refused()
    {
        var csr = NewCsrDer();
        csr[^1] ^= 0xFF;

        var response = await RequestCertificateAsync(
            Client("oid-cert-tampered", "Mina.Node,Mina.Node.westeurope"), "westeurope", csr);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task A_granted_node_gets_a_certificate_bearing_the_regions_configured_server_name_and_chaining_to_the_ca()
    {
        var response = await RequestCertificateAsync(
            Client("oid-cert-westeurope", "Mina.Node,Mina.Node.westeurope"), "westeurope");
        response.EnsureSuccessStatusCode();

        var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
        using var leaf = X509Certificate2.CreateFromPem(body.GetProperty("certificatePem").GetString());
        using var ca = X509Certificate2.CreateFromPem(body.GetProperty("caCertificatePem").GetString());

        Assert.False(leaf.HasPrivateKey); // the key stayed with this test, which generated the CSR

        var eku = leaf.Extensions.OfType<X509EnhancedKeyUsageExtension>().Single();
        Assert.Contains(eku.EnhancedKeyUsages.Cast<Oid>(), oid => oid.Value == "1.3.6.1.5.5.7.3.1"); // serverAuth

        var san = leaf.Extensions.OfType<X509SubjectAlternativeNameExtension>().Single().Format(false);
        Assert.Contains("westeurope.egress.mina", san, StringComparison.Ordinal);

        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(ca);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        Assert.True(chain.Build(leaf));
    }
}
