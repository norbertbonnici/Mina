using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace Mina.ControlPlane.Api.Tests;

/// <summary>
/// The role x endpoint matrix THREAT_MODEL B7 names directly ("server-side rejection... app-role
/// checks in API not UI... Test: authorisation matrix tests") and TEST_STRATEGY §3 lists as its own
/// row ("authorisation matrix (Analyst/Approver/Admin x every API operation)"). Every other test
/// file in this project proves its own feature works for the role that should hold it; this file's
/// only job is the other direction -- that every route refuses every role that is not its own.
/// </summary>
/// <remarks>
/// Catches a forgotten `.RequireAuthorization(policy)` (indistinguishable at compile time from a
/// deliberate bare `.RequireAuthorization()`) on routes whose only guard is that policy -- verified
/// by mutation: removing <c>AnalystPolicy</c> from <c>GET /api/regions</c> fails this file
/// immediately. It does **not** catch the same mistake on the three node routes, which also carry
/// an independent in-handler check (<c>NodeRegionGrant.IsGrantedFor</c>): removing the route-level
/// <c>NodePolicy</c> there left 32 of 33 cases here still green, because a wrong-role caller still
/// got refused, just by the other layer instead. That is real defence in depth for those specific
/// routes, not a hole this file can see through from the status code alone. Since M2-6's close-out
/// <see cref="Node_route_refusals_say_which_layer_refused"/> asserts on the body: the policy's 403
/// is empty, the handler's carries a problem+json naming the region grant, so removing the route
/// policy now fails this file on the node routes too.
/// </remarks>
public sealed class AuthorisationMatrixTests(MinaApiFactory factory) : IClassFixture<MinaApiFactory>
{
    private const string Analyst = "Mina.Analyst";
    private const string Approver = "Mina.Approver";
    private const string Node = "Mina.Node,Mina.Node.westeurope";
    private const string Admin = "Mina.Admin";
    private const string TelemetryViewer = "Mina.TelemetryViewer";

    private static readonly string[] AllRoleSets = [Analyst, Approver, Node, Admin, TelemetryViewer];

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

    private static byte[] NewCsrDer()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return new CertificateRequest("CN=mina-node", key, HashAlgorithmName.SHA256).CreateSigningRequest();
    }

    /// <summary>
    /// Every policy-gated route, its verb, and the one role set that should be able to pass its
    /// policy check (not necessarily succeed the business logic -- a fabricated id still clears
    /// authorization and fails later, which is the point: this file tests the authorization layer
    /// in isolation from whatever the handler does next). Random GUIDs are deliberate: policy
    /// evaluation runs before the handler touches the repository, so a wrong role must be refused
    /// before "does this id exist" is ever asked.
    /// </summary>
    public static IEnumerable<object[]> PolicyGatedRoutes()
    {
        var randomId = Guid.NewGuid();
        yield return [HttpMethod.Get, "/api/regions", Analyst];
        yield return [HttpMethod.Post, "/api/sessions", Analyst];
        yield return [HttpMethod.Post, $"/api/sessions/{randomId}/renew", Analyst];
        yield return [HttpMethod.Delete, $"/api/sessions/{randomId}", Analyst];
        yield return [HttpMethod.Post, $"/api/sessions/{randomId}/sensitive", Analyst];
        yield return [HttpMethod.Get, "/api/sensitive-requests/pending", Approver];
        yield return [HttpMethod.Post, $"/api/sensitive-requests/{randomId}/approve", Approver];
        yield return [HttpMethod.Post, $"/api/sensitive-requests/{randomId}/deny", Approver];
        yield return [HttpMethod.Post, $"/api/sensitive-requests/{randomId}/activate", Analyst];
        yield return [HttpMethod.Delete, $"/api/sensitive-requests/{randomId}", Analyst];
        yield return [HttpMethod.Get, "/api/nodes/westeurope/sessions", Node];
        yield return [HttpMethod.Post, "/api/nodes/telemetry", Node];
        yield return [HttpMethod.Post, "/api/nodes/westeurope/certificate", Node];
        yield return [HttpMethod.Get, "/api/audit/recent", Admin];
        yield return [HttpMethod.Get, "/api/audit/verify", Admin];
        yield return [HttpMethod.Get, "/api/browsing-data", TelemetryViewer];
        yield return [HttpMethod.Get, "/api/browsing-data/analysts", TelemetryViewer];
    }

    [Theory]
    [MemberData(nameof(PolicyGatedRoutes))]
    public async Task Every_role_that_is_not_the_routes_own_is_refused(HttpMethod method, string path, string ownRoles)
    {
        foreach (var roles in AllRoleSets)
        {
            if (roles == ownRoles)
            {
                continue; // covered as a positive case in each feature's own test file
            }

            using var request = new HttpRequestMessage(method, new Uri(path, UriKind.Relative));
            if (method == HttpMethod.Post)
            {
                request.Content = JsonContent.Create(new { });
            }

            using var response = await Client($"oid-matrix-{roles.GetHashCode():x}", roles)
                .SendAsync(request);

            Assert.True(
                response.StatusCode == HttpStatusCode.Forbidden,
                $"{method} {path}: expected 403 for roles '{roles}' (route belongs to '{ownRoles}'), got {response.StatusCode}");
        }
    }

    [Theory]
    [MemberData(nameof(PolicyGatedRoutes))]
    public async Task Anonymous_is_refused_on_every_policy_gated_route(HttpMethod method, string path, string ownRoles)
    {
        _ = ownRoles;
        using var request = new HttpRequestMessage(method, new Uri(path, UriKind.Relative));
        if (method == HttpMethod.Post)
        {
            request.Content = JsonContent.Create(new { });
        }

        using var response = await _factory.CreateClient().SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    /// <summary>
    /// The one route with no policy at the mapping layer at all (`GET /api/sensitive-requests/{id}`
    /// is `.RequireAuthorization()` bare, filtered inside <c>SensitiveSessionService.GetAsync</c>) --
    /// every other route in this file gets its guarantee from routing; this one gets it from the
    /// service, which is a real design choice (letting the response be 404 rather than 403, so a
    /// stranger cannot distinguish "not yours" from "doesn't exist") but means the routing-layer
    /// matrix above does not cover it. Proven against a request that genuinely exists, so a bug that
    /// made the service 404 *everything* would not show up as a false pass here.
    /// </summary>
    [Fact]
    public async Task A_bare_authenticated_role_with_no_stake_in_a_sensitive_request_gets_not_found_not_forbidden()
    {
        var analyst = Client("oid-matrix-owner", Analyst);
        var issue = await analyst.PostAsJsonAsync(
            new Uri("/api/sessions", UriKind.Relative), new { region = "westeurope", csrPem = NewCsrPem() });
        issue.EnsureSuccessStatusCode();
        var sessionId = JsonDocument.Parse(await issue.Content.ReadAsStringAsync())
            .RootElement.GetProperty("sessionId").GetGuid();

        var created = await analyst.PostAsJsonAsync(
            new Uri($"/api/sessions/{sessionId}/sensitive", UriKind.Relative),
            new { justificationReference = "CASE-MATRIX", requestedMinutes = 60 });
        created.EnsureSuccessStatusCode();
        var requestId = JsonDocument.Parse(await created.Content.ReadAsStringAsync())
            .RootElement.GetProperty("requestId").GetGuid();

        foreach (var roles in new[] { Node, Admin })
        {
            var response = await Client($"oid-matrix-stranger-{roles.GetHashCode():x}", roles)
                .GetAsync(new Uri($"/api/sensitive-requests/{requestId}", UriKind.Relative));

            Assert.True(
                response.StatusCode == HttpStatusCode.NotFound,
                $"roles '{roles}' with no stake in request {requestId}: expected 404, got {response.StatusCode}");
        }

        // Positive control: the actual requester and a real approver both still see it, so the
        // 404s above are the service's own requester/approver filter, not a route that 404s always.
        var ownerCheck = await analyst.GetAsync(new Uri($"/api/sensitive-requests/{requestId}", UriKind.Relative));
        ownerCheck.EnsureSuccessStatusCode();
        var approverCheck = await Client("oid-matrix-approver", Approver)
            .GetAsync(new Uri($"/api/sensitive-requests/{requestId}", UriKind.Relative));
        approverCheck.EnsureSuccessStatusCode();
    }

    /// <summary>
    /// The node interface is scoped twice -- role, then region -- and the matrix above only proves
    /// the role half (using a node granted westeurope throughout, since that is what the shared
    /// config in <see cref="MinaApiFactory"/> has an egress entry for). This is the same check for
    /// the two region-gated routes, for completeness -- not, on its own, proof against
    /// <c>NodeRegionGrant</c>'s in-handler check being bypassed: a 403 here can come from either
    /// layer, and this test does not distinguish which (see the class remarks above). What it does
    /// add over the main matrix is coverage of a real csr body on the certificate route, rather
    /// than the empty object every POST case there uses.
    /// </summary>
    [Fact]
    public async Task Approver_and_admin_are_refused_the_node_interface_same_as_analyst()
    {
        foreach (var roles in new[] { Approver, Admin })
        {
            var allowlist = await Client($"oid-matrix-node-{roles}", roles)
                .GetAsync(new Uri("/api/nodes/westeurope/sessions", UriKind.Relative));
            Assert.Equal(HttpStatusCode.Forbidden, allowlist.StatusCode);

            using var certContent = new ByteArrayContent(NewCsrDer());
            certContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
            var cert = await Client($"oid-matrix-cert-{roles}", roles)
                .PostAsync(new Uri("/api/nodes/westeurope/certificate", UriKind.Relative), certContent);
            Assert.Equal(HttpStatusCode.Forbidden, cert.StatusCode);
        }
    }

    /// <summary>
    /// Closes the blind spot the class remarks describe. For each node route, a wrong-role caller
    /// must be refused by the route policy (an empty 403 -- the handler never ran) and a right-role,
    /// wrong-region node by the handler's own grant check (a 403 whose body names the region). The
    /// two layers are distinguishable only here, so this is the one place a forgotten route policy
    /// on a node route shows up: it would turn the first case's empty body into the second's message.
    /// </summary>
    [Fact]
    public async Task Node_route_refusals_say_which_layer_refused()
    {
        var otherRegionNode = "Mina.Node,Mina.Node.northeurope";
        using var csr = new ByteArrayContent(NewCsrDer());
        csr.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");

        var cases = new (HttpMethod Method, string Path, Func<HttpContent?> Body)[]
        {
            (HttpMethod.Get, "/api/nodes/westeurope/sessions", () => null),
            (HttpMethod.Post, "/api/nodes/telemetry", () => JsonContent.Create(new { region = "westeurope", items = Array.Empty<object>() })),
            (HttpMethod.Post, "/api/nodes/westeurope/certificate", () => new ByteArrayContent(NewCsrDer())
            {
                Headers = { ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream") },
            }),
        };

        foreach (var (method, path, body) in cases)
        {
            // Wrong role: the policy refuses before any handler code runs, so there is no body.
            using var wrongRole = new HttpRequestMessage(method, new Uri(path, UriKind.Relative)) { Content = body() };
            using var byPolicy = await Client("oid-matrix-body-analyst", Analyst).SendAsync(wrongRole);
            Assert.Equal(HttpStatusCode.Forbidden, byPolicy.StatusCode);
            Assert.Equal(string.Empty, await byPolicy.Content.ReadAsStringAsync());

            // Right role, wrong region: the policy passes and the handler's grant check refuses,
            // and says so.
            using var wrongRegion = new HttpRequestMessage(method, new Uri(path, UriKind.Relative)) { Content = body() };
            using var byHandler = await Client("oid-matrix-body-neu", otherRegionNode).SendAsync(wrongRegion);
            Assert.Equal(HttpStatusCode.Forbidden, byHandler.StatusCode);
            var text = await byHandler.Content.ReadAsStringAsync();
            Assert.Contains("not granted region 'westeurope'", text, StringComparison.Ordinal);
        }
    }

    /// <summary>
    /// Holding two roles at once is a real Entra assignment shape (nothing stops an operator from
    /// granting both), and B7's own scenario is exactly this for Analyst+Approver (self-approval).
    /// This is the same check for Node+Analyst: a compromised or misconfigured node identity must
    /// not gain analyst-only session issuance just by also holding the node role, and vice versa --
    /// each policy is `RequireRole`, independently, not `RequireRole(A) OR RequireRole(B)`, so this
    /// should already hold; asserted rather than assumed.
    /// </summary>
    [Fact]
    public async Task Holding_both_node_and_analyst_roles_grants_only_what_each_role_grants_on_its_own()
    {
        var both = Client("oid-matrix-dual", $"{Analyst},{Node}");

        var issue = await both.PostAsJsonAsync(
            new Uri("/api/sessions", UriKind.Relative), new { region = "westeurope", csrPem = NewCsrPem() });
        Assert.Equal(HttpStatusCode.Created, issue.StatusCode); // the Analyst half still works

        var allowlist = await both.GetAsync(new Uri("/api/nodes/westeurope/sessions", UriKind.Relative));
        Assert.Equal(HttpStatusCode.OK, allowlist.StatusCode); // the Node half still works

        // Neither role implies Approver or Admin.
        var pending = await both.GetAsync(new Uri("/api/sensitive-requests/pending", UriKind.Relative));
        Assert.Equal(HttpStatusCode.Forbidden, pending.StatusCode);
        var audit = await both.GetAsync(new Uri("/api/audit/recent", UriKind.Relative));
        Assert.Equal(HttpStatusCode.Forbidden, audit.StatusCode);
    }
}
