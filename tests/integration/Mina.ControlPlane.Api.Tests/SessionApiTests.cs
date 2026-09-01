using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace Mina.ControlPlane.Api.Tests;

public sealed class SessionApiTests(MinaApiFactory factory) : IClassFixture<MinaApiFactory>
{
    private readonly MinaApiFactory _factory = factory;

    private HttpClient AnalystClient(string oid = "oid-1", string device = "device-1", string roles = "Mina.Analyst")
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Test-Oid", oid);
        client.DefaultRequestHeaders.Add("X-Test-Upn", $"{oid}@fiaumalta.org");
        if (!string.IsNullOrEmpty(device))
        {
            client.DefaultRequestHeaders.Add("X-Test-Device", device);
        }

        if (!string.IsNullOrEmpty(roles))
        {
            client.DefaultRequestHeaders.Add("X-Test-Roles", roles);
        }

        return client;
    }

    private static string NewCsrPem()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var der = new CertificateRequest("CN=mina-agent", key, HashAlgorithmName.SHA256).CreateSigningRequest();
        return PemEncoding.WriteString("CERTIFICATE REQUEST", der);
    }

    [Fact]
    public async Task Anonymous_request_is_unauthorized()
    {
        var client = _factory.CreateClient();

        var response = await client.GetAsync(new Uri("/api/regions", UriKind.Relative));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Regions_lists_only_selectable_regions()
    {
        var response = await AnalystClient().GetAsync(new Uri("/api/regions", UriKind.Relative));
        response.EnsureSuccessStatusCode();

        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var regions = doc.RootElement.GetProperty("regions").EnumerateArray().Select(e => e.GetString()!).ToArray();

        Assert.Equal(["westeurope"], regions); // francecentral approved-but-inactive, northeurope inactive
    }

    [Fact]
    public async Task Issue_returns_a_certificate_and_egress_for_an_analyst()
    {
        var response = await AnalystClient().PostAsJsonAsync(
            new Uri("/api/sessions", UriKind.Relative), new { region = "westeurope", csrPem = NewCsrPem() });

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var root = doc.RootElement;

        Assert.Equal("westeurope", root.GetProperty("region").GetString());
        Assert.Equal("20.0.0.1", root.GetProperty("egressHost").GetString());
        var pem = root.GetProperty("certificatePem").GetString()!;
        Assert.StartsWith("-----BEGIN CERTIFICATE-----", pem, StringComparison.Ordinal);

        // The issued certificate is real and carries the session id in its SAN.
        using var cert = X509Certificate2.CreateFromPem(pem);
        var sessionId = root.GetProperty("sessionId").GetGuid();
        var san = cert.Extensions.OfType<X509SubjectAlternativeNameExtension>().Single().Format(false);
        Assert.Contains($"mina:session:{sessionId:D}", san, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Issue_for_an_inactive_but_approved_region_is_forbidden()
    {
        var response = await AnalystClient().PostAsJsonAsync(
            new Uri("/api/sessions", UriKind.Relative), new { region = "francecentral", csrPem = NewCsrPem() });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Issue_without_the_analyst_role_is_forbidden()
    {
        var client = AnalystClient(roles: "Mina.Approver");

        var response = await client.PostAsJsonAsync(
            new Uri("/api/sessions", UriKind.Relative), new { region = "westeurope", csrPem = NewCsrPem() });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Issue_from_a_noncompliant_device_is_forbidden()
    {
        var client = AnalystClient(device: ""); // no device id ⇒ treated as non-compliant

        var response = await client.PostAsJsonAsync(
            new Uri("/api/sessions", UriKind.Relative), new { region = "westeurope", csrPem = NewCsrPem() });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Issue_with_a_malformed_csr_is_bad_request()
    {
        var response = await AnalystClient().PostAsJsonAsync(
            new Uri("/api/sessions", UriKind.Relative), new { region = "westeurope", csrPem = "not a pem" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Full_lifecycle_issue_renew_end()
    {
        var client = AnalystClient(oid: "oid-lifecycle");

        var issue = await client.PostAsJsonAsync(
            new Uri("/api/sessions", UriKind.Relative), new { region = "westeurope", csrPem = NewCsrPem() });
        Assert.Equal(HttpStatusCode.Created, issue.StatusCode);
        var sessionId = JsonDocument.Parse(await issue.Content.ReadAsStringAsync())
            .RootElement.GetProperty("sessionId").GetGuid();

        var renew = await client.PostAsJsonAsync(
            new Uri($"/api/sessions/{sessionId}/renew", UriKind.Relative), new { csrPem = NewCsrPem() });
        Assert.Equal(HttpStatusCode.OK, renew.StatusCode);

        var end = await client.DeleteAsync(new Uri($"/api/sessions/{sessionId}", UriKind.Relative));
        Assert.Equal(HttpStatusCode.NoContent, end.StatusCode);
    }

    [Theory]
    [InlineData("westeurope\u0000")]
    [InlineData("not a region")]
    [InlineData("evil.example.com")]
    public async Task A_malformed_region_is_rejected_before_it_reaches_metrics_or_audit(string region)
    {
        var response = await AnalystClient().PostAsJsonAsync(
            new Uri("/api/sessions", UriKind.Relative), new { region, csrPem = NewCsrPem() });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task An_oversized_region_cannot_stop_the_denial_being_recorded()
    {
        // Audit is written before the action, so an audit write that fails suppresses the action's
        // record. A region long enough to overflow the audit payload must therefore be refused at
        // the boundary rather than carried into the audit event.
        var region = new string('a', 5000);

        var response = await AnalystClient().PostAsJsonAsync(
            new Uri("/api/sessions", UriKind.Relative), new { region, csrPem = NewCsrPem() });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.NotEqual(HttpStatusCode.InternalServerError, response.StatusCode);
    }

    [Fact]
    public async Task Renewing_an_ended_session_is_a_conflict_not_a_server_error()
    {
        var client = AnalystClient(oid: "oid-ended");
        var issue = await client.PostAsJsonAsync(
            new Uri("/api/sessions", UriKind.Relative), new { region = "westeurope", csrPem = NewCsrPem() });
        var sessionId = JsonDocument.Parse(await issue.Content.ReadAsStringAsync())
            .RootElement.GetProperty("sessionId").GetGuid();

        await client.DeleteAsync(new Uri($"/api/sessions/{sessionId}", UriKind.Relative));

        var renew = await client.PostAsJsonAsync(
            new Uri($"/api/sessions/{sessionId}/renew", UriKind.Relative), new { csrPem = NewCsrPem() });

        // The session exists but is ended: a caller-side condition, so 409 — not an unhandled 500.
        Assert.Equal(HttpStatusCode.Conflict, renew.StatusCode);
    }

    [Fact]
    public async Task A_session_cannot_be_renewed_by_a_different_user()
    {
        var owner = AnalystClient(oid: "oid-owner");
        var issue = await owner.PostAsJsonAsync(
            new Uri("/api/sessions", UriKind.Relative), new { region = "westeurope", csrPem = NewCsrPem() });
        var sessionId = JsonDocument.Parse(await issue.Content.ReadAsStringAsync())
            .RootElement.GetProperty("sessionId").GetGuid();

        var attacker = AnalystClient(oid: "oid-attacker");
        var renew = await attacker.PostAsJsonAsync(
            new Uri($"/api/sessions/{sessionId}/renew", UriKind.Relative), new { csrPem = NewCsrPem() });

        Assert.Equal(HttpStatusCode.NotFound, renew.StatusCode);
    }

    [Fact]
    public async Task Another_users_session_is_indistinguishable_from_one_that_does_not_exist()
    {
        var owner = AnalystClient(oid: "oid-owner");
        var issue = await owner.PostAsJsonAsync(
            new Uri("/api/sessions", UriKind.Relative), new { region = "westeurope", csrPem = NewCsrPem() });
        var realSessionId = JsonDocument.Parse(await issue.Content.ReadAsStringAsync())
            .RootElement.GetProperty("sessionId").GetGuid();

        var attacker = AnalystClient(oid: "oid-attacker");

        // The whole response, not just the status: an empty 404 and a problem+json body saying
        // "Denied: NotSessionOwner" are different answers even when both are refusals, and the
        // difference is exactly the existence oracle.
        var real = await attacker.PostAsJsonAsync(
            new Uri($"/api/sessions/{realSessionId}/renew", UriKind.Relative), new { csrPem = NewCsrPem() });
        var invented = await attacker.PostAsJsonAsync(
            new Uri($"/api/sessions/{Guid.NewGuid()}/renew", UriKind.Relative), new { csrPem = NewCsrPem() });

        Assert.Equal(invented.StatusCode, real.StatusCode);
        Assert.Equal(
            await invented.Content.ReadAsStringAsync(),
            await real.Content.ReadAsStringAsync());
        Assert.Equal(
            invented.Content.Headers.ContentType?.ToString(),
            real.Content.Headers.ContentType?.ToString());

        // Deleting has the same shape, and so does a request id on the suppression routes.
        var deleteReal = await attacker.DeleteAsync(
            new Uri($"/api/sessions/{realSessionId}", UriKind.Relative));
        var deleteInvented = await attacker.DeleteAsync(
            new Uri($"/api/sessions/{Guid.NewGuid()}", UriKind.Relative));
        Assert.Equal(deleteInvented.StatusCode, deleteReal.StatusCode);
        Assert.Equal(
            await deleteInvented.Content.ReadAsStringAsync(),
            await deleteReal.Content.ReadAsStringAsync());
    }
}
