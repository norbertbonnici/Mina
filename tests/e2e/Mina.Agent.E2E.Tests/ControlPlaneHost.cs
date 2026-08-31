using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Mina.ControlPlane.Api.Infrastructure;
using Mina.ControlPlane.Pki;

namespace Mina.Agent.E2E.Tests;

/// <summary>
/// Hosts the real control-plane API for the end-to-end tests, with two substitutions: Entra token
/// validation becomes <see cref="BearerTestAuthHandler"/>, and the issuing CA is one the test also
/// gave to the egress, so a session certificate the API signs is one the egress will accept. Every
/// other layer — authorization policy, session service, CSR signing, repository — is production
/// wiring.
/// </summary>
public sealed class ControlPlaneHost(
    CertificateAuthority authority,
    string egressHost,
    int egressPort,
    string egressServerName,
    TimeSpan leaseTtl) : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((_, cfg) => cfg.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["AzureAd:Instance"] = "https://login.microsoftonline.com/",
            ["AzureAd:TenantId"] = "11111111-1111-1111-1111-111111111111",
            ["AzureAd:ClientId"] = "22222222-2222-2222-2222-222222222222",
            ["Mina:Session:AnalystRole"] = "Mina.Analyst",
            ["Mina:Session:LeaseTtl"] = leaseTtl.ToString(),
            ["Mina:Regions:Approved:0"] = "westeurope",
            ["Mina:Regions:Approved:1"] = "francecentral", // approved but never activated
            ["Mina:Regions:Active:0"] = "westeurope",
            ["Mina:Egress:Regions:westeurope:Host"] = egressHost,
            ["Mina:Egress:Regions:westeurope:Port"] = egressPort.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["Mina:Egress:Regions:westeurope:ServerName"] = egressServerName,
        }));

        builder.ConfigureTestServices(services =>
        {
            services.AddAuthentication(BearerTestAuthHandler.SchemeName)
                .AddScheme<AuthenticationSchemeOptions, BearerTestAuthHandler>(
                    BearerTestAuthHandler.SchemeName, _ => { });

            services.RemoveAll<ICertificateAuthorityProvider>();
            services.AddSingleton<ICertificateAuthorityProvider>(new FixedCertificateAuthorityProvider(authority));
        });
    }

    private sealed class FixedCertificateAuthorityProvider(CertificateAuthority authority) : ICertificateAuthorityProvider
    {
        public CertificateAuthority GetAuthority() => authority;
    }
}
