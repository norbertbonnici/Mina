using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Mina.ControlPlane.Api.Tests;

/// <summary>
/// ADR-0006 constraint 1. The node-facing listener is published from the on-premises DMZ to the internet;
/// the approvals API, the audit read API and the analyst session API must not be reachable there —
/// and must not become reachable through a reverse-proxy mistake, which is why the separation is by
/// the local port the connection was accepted on rather than by proxy path rules.
/// </summary>
/// <remarks>
/// These run against real Kestrel sockets rather than the in-memory test server: the property under
/// test is about which socket accepted the connection, and <c>TestServer</c> has no sockets at all.
/// A test host that could not tell the two listeners apart would pass every assertion here while
/// proving nothing.
/// </remarks>
public sealed class ListenerSeparationTests : IAsyncLifetime, IDisposable
{
    private const int NodePort = 18651;
    private const int ManagementPort = 18652;

    private SeparatedFactory _factory = null!;

    public Task InitializeAsync()
    {
        _factory = new SeparatedFactory();
        _factory.Start();
        return Task.CompletedTask;
    }

    public Task DisposeAsync()
    {
        Dispose();
        return Task.CompletedTask;
    }

    public void Dispose() => _factory?.Dispose();

    [Theory]
    [InlineData("/api/audit/recent")]
    [InlineData("/api/audit/verify")]
    [InlineData("/api/sensitive-requests/pending")]
    [InlineData("/api/regions")]
    public async Task The_management_surface_is_absent_from_the_published_listener(string path)
    {
        using var client = Client(NodePort, "Mina.Admin,Mina.Approver,Mina.Analyst");

        var response = await client.GetAsync(new Uri(path, UriKind.Relative));

        // 404, and specifically not 401 or 403: on this listener the endpoint does not exist. An
        // authentication challenge would confirm to an internet caller that the audit API is there.
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Theory]
    [InlineData("/api/audit/recent")]
    [InlineData("/api/sensitive-requests/pending")]
    [InlineData("/api/regions")]
    public async Task The_same_endpoints_answer_on_the_corporate_listener(string path)
    {
        // The control leg. Without it, the 404s above would equally be explained by the endpoints
        // not existing at all, or by the roles being wrong.
        using var client = Client(ManagementPort, "Mina.Admin,Mina.Approver,Mina.Analyst");

        var response = await client.GetAsync(new Uri(path, UriKind.Relative));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task The_node_api_answers_only_on_the_published_listener()
    {
        using var onNode = Client(NodePort, "Mina.Node,Mina.Node.westeurope");
        using var onManagement = Client(ManagementPort, "Mina.Node,Mina.Node.westeurope");

        var published = await onNode.GetAsync(new Uri("/api/nodes/westeurope/sessions", UriKind.Relative));
        var corporate = await onManagement.GetAsync(new Uri("/api/nodes/westeurope/sessions", UriKind.Relative));

        Assert.Equal(HttpStatusCode.OK, published.StatusCode);

        // The separation cuts both ways. It is not a security property in this direction, but a
        // node endpoint answering on the corporate listener would mean the metadata was not applied.
        Assert.Equal(HttpStatusCode.NotFound, corporate.StatusCode);
    }

    [Fact]
    public async Task A_forwarded_header_cannot_move_a_request_to_the_other_listener()
    {
        // The mechanism has to survive a caller who knows about it. Host, scheme and forwarded
        // headers are all client-supplied; the accepting socket is not.
        using var client = Client(NodePort, "Mina.Admin");
        client.DefaultRequestHeaders.Add("X-Forwarded-Host", $"localhost:{ManagementPort}");
        client.DefaultRequestHeaders.Add("X-Forwarded-Proto", "https");
        client.DefaultRequestHeaders.Add("X-Forwarded-Port", ManagementPort.ToString(System.Globalization.CultureInfo.InvariantCulture));
        client.DefaultRequestHeaders.Host = $"localhost:{ManagementPort}";

        var response = await client.GetAsync(new Uri("/api/audit/recent", UriKind.Relative));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Theory]
    [InlineData("/api/audit/recent")]
    [InlineData("/api/sensitive-requests/pending")]
    [InlineData("/api/regions")]
    [InlineData("/api/sessions")]
    public async Task A_wrong_method_does_not_disclose_the_management_surface(string path)
    {
        // The gap every other case here misses, because they all probe an endpoint with the verb it
        // accepts. When the path matches a route but the method does not, ASP.NET Core substitutes a
        // synthetic 405 endpoint that carries no metadata at all — including no listener metadata.
        // A middleware that treats "no listener declared" as "serve it" therefore answers 405 with
        // an Allow header on the published port, which enumerates the whole management route table
        // and its verbs to an unauthenticated internet caller.
        using var client = Client(NodePort, "Mina.Admin,Mina.Approver,Mina.Analyst");

        using var request = new HttpRequestMessage(HttpMethod.Options, new Uri(path, UriKind.Relative));
        var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.DoesNotContain(response.Content.Headers, h =>
            h.Key.Equals("Allow", StringComparison.OrdinalIgnoreCase));
        Assert.Null(response.Headers.Location);
    }

    [Fact]
    public async Task A_wrong_method_still_answers_normally_on_the_corporate_listener()
    {
        // The control leg: 405 is the correct answer there, so the fix must not turn every
        // method mismatch into a 404 everywhere.
        using var client = Client(ManagementPort, "Mina.Admin");

        using var request = new HttpRequestMessage(
            HttpMethod.Options, new Uri("/api/audit/recent", UriKind.Relative));
        var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.MethodNotAllowed, response.StatusCode);
    }

    [Fact]
    public async Task The_health_probe_answers_on_both_listeners()
    {
        // Each listener is fronted by something that needs to health-check it.
        using var onNode = Client(NodePort, roles: null);
        using var onManagement = Client(ManagementPort, roles: null);

        Assert.Equal(
            HttpStatusCode.OK,
            (await onNode.GetAsync(new Uri("/healthz", UriKind.Relative))).StatusCode);
        Assert.Equal(
            HttpStatusCode.OK,
            (await onManagement.GetAsync(new Uri("/healthz", UriKind.Relative))).StatusCode);
    }

    private static HttpClient Client(int port, string? roles)
    {
        var client = new HttpClient
        {
            BaseAddress = new Uri($"http://127.0.0.1:{port}"),
            Timeout = TimeSpan.FromSeconds(20),
        };

        if (roles is not null)
        {
            client.DefaultRequestHeaders.Add("X-Test-Oid", "oid-listener");
            client.DefaultRequestHeaders.Add("X-Test-Device", "device-1");
            client.DefaultRequestHeaders.Add("X-Test-Roles", roles);
        }

        return client;
    }

    /// <summary>
    /// The real API on two real Kestrel ports. <see cref="WebApplicationFactory{T}"/> is used only
    /// to reuse the host configuration; the in-memory test server is bypassed by starting Kestrel.
    /// </summary>
    private sealed class SeparatedFactory : WebApplicationFactory<Program>
    {
        private IHost? _host;

        public void Start() => _ = Services;

        protected override IHost CreateHost(IHostBuilder builder)
        {
            // Two hosts from one builder. WebApplicationFactory requires the host it is given back
            // to be serving a TestServer, but TestServer has no sockets — and the property under
            // test is which socket accepted the connection. So the in-memory host is built and
            // returned to satisfy the factory, and a second, identically configured host runs real
            // Kestrel on the two ports the tests actually talk to.
            var inMemory = builder.Build();

            builder.ConfigureWebHost(web => web.UseKestrel());
            _host = builder.Build();
            _host.Start();

            inMemory.Start();
            return inMemory;
        }

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Development");
            builder.UseSetting($"{MinaListenerOptionsSection}:NodePort", NodePort.ToString(System.Globalization.CultureInfo.InvariantCulture));
            builder.UseSetting($"{MinaListenerOptionsSection}:ManagementPort", ManagementPort.ToString(System.Globalization.CultureInfo.InvariantCulture));

            builder.ConfigureAppConfiguration((_, cfg) => cfg.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["AzureAd:Instance"] = "https://login.microsoftonline.com/",
                ["AzureAd:TenantId"] = "11111111-1111-1111-1111-111111111111",
                ["AzureAd:ClientId"] = "22222222-2222-2222-2222-222222222222",
                ["Mina:Regions:Approved:0"] = "westeurope",
                ["Mina:Regions:Active:0"] = "westeurope",
                ["Mina:Egress:Regions:westeurope:Host"] = "20.0.0.1",
                ["Mina:Egress:Regions:westeurope:Port"] = "443",
                ["Mina:Egress:Regions:westeurope:ServerName"] = "westeurope.egress.mina",
            }));

            builder.ConfigureTestServices(services =>
                services.AddAuthentication(TestAuthHandler.SchemeName)
                    .AddScheme<AuthenticationSchemeOptions, TestAuthHandler>(TestAuthHandler.SchemeName, _ => { }));
        }

        private const string MinaListenerOptionsSection = "Mina:Hosting:Listeners";

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _host?.StopAsync().GetAwaiter().GetResult();
                _host?.Dispose();
            }

            base.Dispose(disposing);
        }
    }
}
