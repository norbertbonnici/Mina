using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Mina.ControlPlane.Api.Tests;

/// <summary>
/// The Conditional Access authentication-context gate. A `deviceid` claim proves the device is
/// Entra-<em>registered</em>, not that it satisfies an Intune compliance policy — a registered
/// device that is actively non-compliant emits exactly the same claim. Requiring an auth context is
/// the only way this API can demand that a CA policy granting on "device marked as compliant" was
/// actually evaluated for the token in front of it.
/// </summary>
public sealed class AuthenticationContextTests : IClassFixture<AuthContextApiFactory>
{
    private readonly AuthContextApiFactory _factory;

    public AuthenticationContextTests(AuthContextApiFactory factory) => _factory = factory;

    [Fact]
    public async Task A_device_bound_token_without_the_auth_context_gets_a_claims_challenge()
    {
        var response = await Client(acrs: null).PostAsJsonAsync(
            new Uri("/api/sessions", UriKind.Relative), new { region = "westeurope", csrPem = NewCsrPem() });

        // 401 with a challenge, not 403: a compliant device must be able to step up silently, and a
        // flat refusal would be indistinguishable from "this device can never comply".
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        var challenge = Assert.Single(response.Headers.WwwAuthenticate);
        Assert.Equal("Bearer", challenge.Scheme);
        Assert.Contains("error=\"insufficient_claims\"", challenge.Parameter, StringComparison.Ordinal);

        // The challenge has to name the context MSAL should ask for, or the client cannot act on it.
        var encoded = challenge.Parameter!
            .Split("claims=\"", StringSplitOptions.None)[1]
            .TrimEnd('"');
        var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
        var acrs = JsonDocument.Parse(decoded).RootElement
            .GetProperty("access_token").GetProperty("acrs");
        Assert.Equal("c1", acrs.GetProperty("value").GetString());
        Assert.True(acrs.GetProperty("essential").GetBoolean());
    }

    [Fact]
    public async Task A_token_carrying_the_auth_context_is_issued_a_session()
    {
        var response = await Client(acrs: "c1").PostAsJsonAsync(
            new Uri("/api/sessions", UriKind.Relative), new { region = "westeurope", csrPem = NewCsrPem() });

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    [Fact]
    public async Task Renewing_a_session_re_checks_the_auth_context_not_just_issuance()
    {
        // B3's mitigation text calls this out specifically: renewal requires "a fresh device-bound
        // Entra token", not a one-time check at issuance a session then coasts on for its whole
        // lease. Issued with the context present; renewed with a token that no longer carries it,
        // the way a token nearing expiry that MSAL silently refreshed without a fresh CA evaluation
        // legitimately could.
        var issued = await Client(acrs: "c1").PostAsJsonAsync(
            new Uri("/api/sessions", UriKind.Relative), new { region = "westeurope", csrPem = NewCsrPem() });
        issued.EnsureSuccessStatusCode();
        var sessionId = JsonDocument.Parse(await issued.Content.ReadAsStringAsync())
            .RootElement.GetProperty("sessionId").GetGuid();

        var renewed = await Client(acrs: null).PostAsJsonAsync(
            new Uri($"/api/sessions/{sessionId}/renew", UriKind.Relative), new { csrPem = NewCsrPem() });

        Assert.Equal(HttpStatusCode.Unauthorized, renewed.StatusCode);
        var challenge = Assert.Single(renewed.Headers.WwwAuthenticate);
        Assert.Contains("error=\"insufficient_claims\"", challenge.Parameter, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_token_with_no_device_id_is_refused_before_the_auth_context_is_considered()
    {
        // Still a 403 rather than a challenge: no auth context can rescue a token that never came
        // from a device-bound flow, so offering a step-up would send the client round a loop.
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Test-Oid", "oid-unbound");
        client.DefaultRequestHeaders.Add("X-Test-Roles", "Mina.Analyst");

        var response = await client.PostAsJsonAsync(
            new Uri("/api/sessions", UriKind.Relative), new { region = "westeurope", csrPem = NewCsrPem() });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Contains("DeviceNotBound", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    private HttpClient Client(string? acrs)
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Test-Oid", "oid-stepup");
        client.DefaultRequestHeaders.Add("X-Test-Roles", "Mina.Analyst");
        client.DefaultRequestHeaders.Add("X-Test-Device", "device-1");
        if (acrs is not null)
        {
            client.DefaultRequestHeaders.Add("X-Test-Acrs", acrs);
        }

        return client;
    }

    private static string NewCsrPem()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=agent", key, HashAlgorithmName.SHA256);
        return PemEncoding.WriteString("CERTIFICATE REQUEST", request.CreateSigningRequest());
    }
}

/// <summary>
/// The API with a Conditional Access authentication context required. Separate from
/// <see cref="MinaApiFactory"/> because turning the requirement on makes every request without the
/// claim a 401, which is exactly what the other suites must not be subjected to.
/// </summary>
public sealed class AuthContextApiFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((_, cfg) => cfg.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["AzureAd:Instance"] = "https://login.microsoftonline.com/",
            ["AzureAd:TenantId"] = "11111111-1111-1111-1111-111111111111",
            ["AzureAd:ClientId"] = "22222222-2222-2222-2222-222222222222",
            ["Mina:Session:RequiredAuthContextId"] = "c1",
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
}
