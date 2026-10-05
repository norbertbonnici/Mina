using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Mina.ControlPlane.Application.Sessions;
using Mina.ControlPlane.Domain.Sessions;
using Mina.ControlPlane.Persistence;

namespace Mina.ControlPlane.Api.Tests;

/// <summary>
/// Checks the composition root when a SQL connection string is configured. No database is
/// contacted — EF does not connect at registration — but resolving the graph catches the failure
/// mode this wiring is prone to: a captive dependency (something long-lived holding the scoped
/// <see cref="MinaDbContext"/>), which would otherwise only appear at runtime under load.
/// </summary>
public sealed class PersistenceWiringTests
{
    private sealed class SqlConfiguredFactory : WebApplicationFactory<Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseSetting("ConnectionStrings:MinaDb", "Server=tcp:unused;Database=Mina;Encrypt=True;");
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

    [Fact]
    public void With_a_connection_string_the_sql_repository_is_used_and_the_graph_resolves()
    {
        using var factory = new SqlConfiguredFactory();

        using var scope = factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<ISessionRepository>();
        var service = scope.ServiceProvider.GetRequiredService<SessionService>();

        Assert.IsType<EfSessionRepository>(repository);
        Assert.NotNull(service);
    }

    [Fact]
    public void Without_a_connection_string_the_in_memory_store_is_used()
    {
        using var factory = new MinaApiFactory();

        using var scope = factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<ISessionRepository>();

        Assert.IsNotType<EfSessionRepository>(repository);
    }
}
