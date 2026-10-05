using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace Mina.ControlPlane.Api.Tests;

/// <summary>
/// The suppression workflow over HTTP: who may ask, who may decide, and the fact that no client can
/// reach suppressed mode without a decision recorded by somebody else (AC-010, AC-011).
/// </summary>
public sealed class SensitiveSessionApiTests(MinaApiFactory factory) : IClassFixture<MinaApiFactory>
{
    private readonly MinaApiFactory _factory = factory;

    private HttpClient Client(string oid, string roles, string device = "device-1")
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Test-Oid", oid);
        client.DefaultRequestHeaders.Add("X-Test-Upn", $"{oid}@example.org");
        client.DefaultRequestHeaders.Add("X-Test-Device", device);
        client.DefaultRequestHeaders.Add("X-Test-Roles", roles);
        return client;
    }

    private HttpClient Analyst(string oid = "oid-a1") => Client(oid, "Mina.Analyst");

    private HttpClient Approver(string oid = "oid-m1") => Client(oid, "Mina.Approver");

    private static string NewCsrPem()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var der = new CertificateRequest("CN=mina-agent", key, HashAlgorithmName.SHA256).CreateSigningRequest();
        return PemEncoding.WriteString("CERTIFICATE REQUEST", der);
    }

    private static async Task<Guid> SessionIdAsync(HttpClient analyst)
    {
        var response = await analyst.PostAsJsonAsync(
            new Uri("/api/sessions", UriKind.Relative), new { region = "westeurope", csrPem = NewCsrPem() });
        response.EnsureSuccessStatusCode();
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync())
            .RootElement.GetProperty("sessionId").GetGuid();
    }

    private static async Task<(HttpStatusCode Status, JsonElement Body)> PostAsync(
        HttpClient client, string path, object? payload = null)
    {
        var response = payload is null
            ? await client.PostAsync(new Uri(path, UriKind.Relative), content: null)
            : await client.PostAsJsonAsync(new Uri(path, UriKind.Relative), payload);
        var text = await response.Content.ReadAsStringAsync();
        var body = string.IsNullOrWhiteSpace(text) ? default : JsonDocument.Parse(text).RootElement.Clone();
        return (response.StatusCode, body);
    }

    private async Task<(HttpClient Analyst, Guid RequestId)> PendingRequestAsync(string oid)
    {
        var analyst = Analyst(oid);
        var sessionId = await SessionIdAsync(analyst);
        var (status, body) = await PostAsync(analyst, $"/api/sessions/{sessionId}/sensitive",
            new { justificationReference = "CASE-2026-0042", requestedMinutes = 120 });
        Assert.Equal(HttpStatusCode.Created, status);
        return (analyst, body.GetProperty("requestId").GetGuid());
    }

    [Fact]
    public async Task Analyst_can_raise_a_request_against_their_session()
    {
        var (_, requestId) = await PendingRequestAsync("oid-raise");

        Assert.NotEqual(Guid.Empty, requestId);
    }

    [Fact]
    public async Task An_approver_without_the_analyst_role_cannot_raise_a_request()
    {
        var analyst = Analyst("oid-owner-1");
        var sessionId = await SessionIdAsync(analyst);

        var (status, _) = await PostAsync(Approver(), $"/api/sessions/{sessionId}/sensitive",
            new { justificationReference = "CASE-1", requestedMinutes = 60 });

        Assert.Equal(HttpStatusCode.Forbidden, status);
    }

    [Fact]
    public async Task A_request_without_a_justification_reference_is_rejected()
    {
        var analyst = Analyst("oid-nojust");
        var sessionId = await SessionIdAsync(analyst);

        var (status, _) = await PostAsync(analyst, $"/api/sessions/{sessionId}/sensitive",
            new { justificationReference = "", requestedMinutes = 60 });

        Assert.Equal(HttpStatusCode.BadRequest, status);
    }

    [Fact]
    public async Task A_duration_beyond_policy_is_rejected()
    {
        var analyst = Analyst("oid-toolong");
        var sessionId = await SessionIdAsync(analyst);

        var (status, _) = await PostAsync(analyst, $"/api/sessions/{sessionId}/sensitive",
            new { justificationReference = "CASE-1", requestedMinutes = 24 * 60 });

        Assert.Equal(HttpStatusCode.BadRequest, status);
    }

    [Fact]
    public async Task An_analyst_cannot_approve_anything()
    {
        var (analyst, requestId) = await PendingRequestAsync("oid-selfapprove");

        var (status, _) = await PostAsync(analyst, $"/api/sensitive-requests/{requestId}/approve",
            new { ttlMinutes = 60 });

        Assert.Equal(HttpStatusCode.Forbidden, status);
    }

    [Fact]
    public async Task An_analyst_who_also_holds_the_approver_role_still_cannot_self_approve()
    {
        var dual = Client("oid-dual", "Mina.Analyst,Mina.Approver");
        var sessionId = await SessionIdAsync(dual);
        var (created, body) = await PostAsync(dual, $"/api/sessions/{sessionId}/sensitive",
            new { justificationReference = "CASE-DUAL", requestedMinutes = 60 });
        Assert.Equal(HttpStatusCode.Created, created);
        var requestId = body.GetProperty("requestId").GetGuid();

        var (status, _) = await PostAsync(dual, $"/api/sensitive-requests/{requestId}/approve",
            new { ttlMinutes = 60 });

        // Passing the role policy is not enough: the control plane refuses self-decision.
        Assert.Equal(HttpStatusCode.Forbidden, status);
    }

    [Fact]
    public async Task Suppression_cannot_be_activated_before_approval()
    {
        var (analyst, requestId) = await PendingRequestAsync("oid-noapproval");

        var (status, _) = await PostAsync(analyst, $"/api/sensitive-requests/{requestId}/activate");

        // AC-010: no approval means no suppressed mode, and it is a state conflict, not a crash.
        Assert.Equal(HttpStatusCode.Conflict, status);
    }

    [Fact]
    public async Task Approve_then_activate_moves_the_session_into_sensitive_mode()
    {
        var analyst = Analyst("oid-happy");
        var sessionId = await SessionIdAsync(analyst);
        var (_, created) = await PostAsync(analyst, $"/api/sessions/{sessionId}/sensitive",
            new { justificationReference = "CASE-HAPPY", requestedMinutes = 120 });
        var requestId = created.GetProperty("requestId").GetGuid();

        var (approveStatus, approved) = await PostAsync(
            Approver(), $"/api/sensitive-requests/{requestId}/approve", new { ttlMinutes = 60 });
        Assert.Equal(HttpStatusCode.OK, approveStatus);
        Assert.Equal("Approved", approved.GetProperty("state").GetString());
        Assert.Equal("oid-m1@example.org", approved.GetProperty("approverUpn").GetString());

        var (activateStatus, activated) = await PostAsync(analyst, $"/api/sensitive-requests/{requestId}/activate");
        Assert.Equal(HttpStatusCode.OK, activateStatus);
        Assert.Equal("ActiveSuppressed", activated.GetProperty("state").GetString());

        // The session's own mode now reports suppression, which is what the agent surfaces (FR-006).
        var renew = await analyst.PostAsJsonAsync(
            new Uri($"/api/sessions/{sessionId}/renew", UriKind.Relative), new { csrPem = NewCsrPem() });
        renew.EnsureSuccessStatusCode();
        var mode = JsonDocument.Parse(await renew.Content.ReadAsStringAsync())
            .RootElement.GetProperty("mode").GetString();
        Assert.Equal("Sensitive", mode);
    }

    [Fact]
    public async Task Denied_requests_cannot_be_activated()
    {
        var (analyst, requestId) = await PendingRequestAsync("oid-denied");

        var (denyStatus, denied) = await PostAsync(Approver(), $"/api/sensitive-requests/{requestId}/deny");
        Assert.Equal(HttpStatusCode.OK, denyStatus);
        Assert.Equal("Denied", denied.GetProperty("state").GetString());

        var (activateStatus, _) = await PostAsync(analyst, $"/api/sensitive-requests/{requestId}/activate");
        Assert.Equal(HttpStatusCode.Conflict, activateStatus);
    }

    [Fact]
    public async Task The_pending_queue_is_approver_only()
    {
        await PendingRequestAsync("oid-queue");

        var forbidden = await Analyst("oid-queue-peek").GetAsync(
            new Uri("/api/sensitive-requests/pending", UriKind.Relative));
        Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);

        var allowed = await Approver().GetAsync(new Uri("/api/sensitive-requests/pending", UriKind.Relative));
        allowed.EnsureSuccessStatusCode();
        var queue = JsonDocument.Parse(await allowed.Content.ReadAsStringAsync()).RootElement;
        Assert.NotEqual(0, queue.GetProperty("requests").GetArrayLength());

        // The queue is a bounded read, so the response has to say whether it is the whole queue.
        // A bare array cannot, and a client would present a truncated page as everything waiting.
        Assert.False(queue.GetProperty("hasMore").GetBoolean());
    }

    [Fact]
    public async Task An_unrelated_analyst_cannot_read_a_request()
    {
        var (_, requestId) = await PendingRequestAsync("oid-private");

        var response = await Analyst("oid-nosy").GetAsync(
            new Uri($"/api/sensitive-requests/{requestId}", UriKind.Relative));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task Anonymous_callers_are_refused()
    {
        var response = await _factory.CreateClient().GetAsync(
            new Uri("/api/sensitive-requests/pending", UriKind.Relative));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}
