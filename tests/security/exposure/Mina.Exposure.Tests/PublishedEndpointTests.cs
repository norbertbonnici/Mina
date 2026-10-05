using System.Net;
using Xunit;

namespace Mina.Exposure.Tests;

/// <summary>
/// The other thing a scanner finds (TEST_STRATEGY §2): the control-plane endpoint published from
/// the DMZ. ADR-0006 constraint 3 says only the node-facing routes may answer there — the analyst
/// session API, the suppression workflow, the audit read API and every administrative endpoint bind
/// a different listener and must not be reachable from the internet.
/// </summary>
/// <remarks>
/// <para>
/// `ListenerSeparationTests` proves the middleware against real Kestrel sockets. What it cannot
/// prove is that the DMZ proxy forwards to the listener everyone thinks it does. A reverse-proxy
/// rule pointing at the management port would publish the approvals UI and the audit API to the
/// internet, and every in-process test would still pass.
/// </para>
/// <para>
/// The distinction that makes this meaningful is 404 versus 401. A node route answers 401 — it
/// exists here and wants a token. A management route answers 404 — as far as this listener is
/// concerned it does not exist at all, which is deliberate: a 401 would confirm to an unauthorised
/// caller that the audit API is there to be attacked. If every route 404s, the endpoint is simply
/// down and the suite is proving nothing, which is why the node route is asserted too.
/// </para>
/// </remarks>
public sealed class PublishedEndpointTests
{
    /// <summary>
    /// Any value matches the {region} route parameter; authentication runs first and answers 401
    /// long before a region is looked at, so this deliberately is not a real region.
    /// </summary>
    private const string AnyRegion = "region-under-test";

    private static readonly HttpClient Client = new() { Timeout = TimeSpan.FromSeconds(20) };

    [SkippableFact]
    public async Task The_published_endpoint_is_up()
    {
        // The control leg: without it, every "must 404" assertion below passes against a dead host.
        var response = await GetAsync("/healthz");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [SkippableFact]
    public async Task The_node_facing_routes_are_published_and_demand_a_token()
    {
        // 401, not 404: these routes belong on this listener. An unauthenticated node gets nothing,
        // but the route is there -- which is what makes the 404s below evidence of separation
        // rather than evidence of an outage.
        foreach (var route in new[]
        {
            $"/api/nodes/{AnyRegion}/sessions",
        })
        {
            var response = await GetAsync(route);

            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }
    }

    [SkippableTheory]
    [InlineData("/api/audit/recent", "the audit read API — the record of every governance action")]
    [InlineData("/api/audit/verify", "audit chain verification")]
    [InlineData("/api/sessions", "the analyst session API")]
    [InlineData("/api/sensitive-requests/pending", "the approver queue")]
    [InlineData("/api/regions", "region administration")]
    public async Task The_management_surface_is_not_reachable_from_the_internet(string route, string what)
    {
        var response = await GetAsync(route);

        Assert.True(
            response.StatusCode == HttpStatusCode.NotFound,
            $"{route} answered {(int)response.StatusCode} on the published endpoint, exposing {what}. "
            + "ADR-0006 constraint 3 requires it to bind the management listener only.");
    }

    private static async Task<HttpResponseMessage> GetAsync(string route)
    {
        var baseAddress = StampUnderTest.ControlPlaneUrl;
        Skip.If(baseAddress is null, StampUnderTest.SkipReason(StampUnderTest.ControlPlaneVariable));

        return await Client.GetAsync(new Uri(new Uri(baseAddress!), route));
    }
}
