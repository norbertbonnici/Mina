using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Mina.ControlPlane.Api.Tests;

/// <summary>
/// Hosts the real control-plane API for tests, with Entra replaced by <see cref="TestAuthHandler"/>
/// and a fixed region/egress configuration. Everything else — the authorization policy, the
/// session service, CSR signing, the in-memory repository — is the production wiring.
/// </summary>
public sealed class MinaApiFactory : WebApplicationFactory<Program>
{
    // francecentral is approved but not active, so it must not be selectable (AC-008).
    private static readonly Dictionary<string, string?> Config = new()
    {
        ["AzureAd:Instance"] = "https://login.microsoftonline.com/",
        ["AzureAd:TenantId"] = "11111111-1111-1111-1111-111111111111",
        ["AzureAd:ClientId"] = "22222222-2222-2222-2222-222222222222",
        ["Mina:Session:AnalystRole"] = "Mina.Analyst",
        ["Mina:Session:LeaseTtl"] = "01:00:00",
        ["Mina:Regions:Approved:0"] = "westeurope",
        ["Mina:Regions:Approved:1"] = "northeurope",
        ["Mina:Regions:Approved:2"] = "francecentral",
        ["Mina:Regions:Active:0"] = "westeurope",
        ["Mina:Egress:Regions:westeurope:Host"] = "20.0.0.1",
        ["Mina:Egress:Regions:westeurope:Port"] = "443",
        ["Mina:Egress:Regions:westeurope:ServerName"] = "westeurope.egress.mina",
    };

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((_, cfg) => cfg.AddInMemoryCollection(Config));

        builder.ConfigureTestServices(services =>
        {
            // Replace Entra with the test scheme and make it the default.
            services.AddAuthentication(TestAuthHandler.SchemeName)
                .AddScheme<AuthenticationSchemeOptions, TestAuthHandler>(TestAuthHandler.SchemeName, _ => { });
        });
    }
}
