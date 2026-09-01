using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Mina.ControlPlane.Api.Tests;

/// <summary>
/// Since ADR-0006 the control plane runs on a VM in the FIAU Proxmox cluster, configured by hand or
/// by a provisioning tool rather than by App Service. Every development stand-in it can fall back to
/// is silent at runtime: an in-memory store looks fine until a restart, and an ephemeral certificate
/// authority looks fine until it stops recognising the certificates it issued a minute ago. A host
/// that is not Development must therefore refuse to start on one.
/// </summary>
public sealed class HostingGuardTests
{
    [Fact]
    public void A_production_host_refuses_to_start_without_a_real_store()
    {
        using var factory = new UnconfiguredProductionFactory();

        // Resolving Services is what builds the host, so this is where the refusal surfaces.
        var failure = Record.Exception(() => _ = factory.Services);

        Assert.NotNull(failure);
        var message = Flatten(failure!);
        Assert.Contains("Refusing to start", message, StringComparison.Ordinal);
        Assert.Contains("ConnectionStrings:MinaDb", message, StringComparison.Ordinal);
    }

    [Fact]
    public void The_stand_ins_can_still_be_accepted_deliberately()
    {
        // The switch exists so a reviewer or a demo can run the whole platform on stand-ins. What it
        // must not be is the default outside Development.
        using var factory = new UnconfiguredProductionFactory(allowFallbacks: true);

        var failure = Record.Exception(() => _ = factory.Services.GetRequiredService<IConfiguration>());

        Assert.Null(failure);
    }

    private static string Flatten(Exception exception)
    {
        var text = new System.Text.StringBuilder();
        for (var current = exception; current is not null; current = current.InnerException)
        {
            text.AppendLine(current.Message);
        }

        return text.ToString();
    }

    /// <summary>
    /// A host that believes it is in production and has been given no store, no certificate
    /// authority and no audit sink — the shape a mistyped deployment produces.
    /// </summary>
    private sealed class UnconfiguredProductionFactory(bool allowFallbacks = false)
        : WebApplicationFactory<Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Production");

            // UseSetting, not ConfigureAppConfiguration: the guard is read while Program.cs is
            // composing the container, which is before configuration callbacks are applied. That is
            // also why it is a real guard — it runs before anything can be resolved.
            builder.UseSetting("Mina:AllowDevelopmentFallbacks", allowFallbacks ? "true" : "false");

            builder.ConfigureAppConfiguration((_, cfg) => cfg.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["AzureAd:Instance"] = "https://login.microsoftonline.com/",
                ["AzureAd:TenantId"] = "11111111-1111-1111-1111-111111111111",
                ["AzureAd:ClientId"] = "22222222-2222-2222-2222-222222222222",
                ["Mina:Regions:Approved:0"] = "westeurope",
                ["Mina:Regions:Active:0"] = "westeurope",
                ["Mina:Egress:Regions:westeurope:Host"] = "20.0.0.1",
                ["Mina:Egress:Regions:westeurope:ServerName"] = "westeurope.egress.mina",
            }));
        }
    }
}
