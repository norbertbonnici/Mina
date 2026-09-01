using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Mina.ControlPlane.Domain.Audit;
using Mina.ControlPlane.Domain.SensitiveSessions;
using Mina.ControlPlane.Domain.Sessions;
using Mina.ControlPlane.Persistence;

namespace Mina.ManagementUi.Tests;

/// <summary>
/// Hosts the real management UI with in-memory stores the test can seed, and with sign-in replaced
/// by a header-driven scheme so each request can present a chosen identity and role set. Every
/// screen, policy and decision endpoint is the production one.
/// </summary>
public sealed class ManagementUiFactory : WebApplicationFactory<Program>
{
    public InMemorySessionRepository Sessions { get; } = new();

    public InMemorySensitiveSessionRepository Requests { get; } = new();

    public InMemoryAuditEventStore Audit { get; } = new();

    protected override IHost CreateHost(IHostBuilder builder)
    {
        builder.UseContentRoot(RepoPath("management-ui", "src", "Mina.ManagementUi"));
        return base.CreateHost(builder);
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");
        builder.ConfigureAppConfiguration((_, cfg) => cfg.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Mina:Regions:Approved:0"] = "westeurope",
            ["Mina:Regions:Approved:1"] = "francecentral",
            ["Mina:Regions:Active:0"] = "westeurope",
            ["Mina:SensitiveSession:ApproverRole"] = "Mina.Approver",
            ["Mina:SensitiveSession:MaxDuration"] = "04:00:00",
            // The application's own dev sign-in is left off; the test scheme below replaces it so
            // identity can vary per request.
            ["Mina:Ui:DevSignIn:Enabled"] = "false",
        }));

        builder.ConfigureTestServices(services =>
        {
            services.AddAuthentication(HeaderAuthHandler.SchemeName)
                .AddScheme<AuthenticationSchemeOptions, HeaderAuthHandler>(HeaderAuthHandler.SchemeName, _ => { });

            services.RemoveAll<ISessionRepository>();
            services.RemoveAll<ISessionQueries>();
            services.RemoveAll<ISensitiveSessionRepository>();
            services.AddSingleton<ISessionRepository>(Sessions);
            services.AddSingleton<ISessionQueries>(Sessions);
            services.AddSingleton<ISensitiveSessionRepository>(Requests);
            services.RemoveAll<IAuditEventStore>();
            services.AddSingleton<IAuditEventStore>(Audit);
        });
    }

    private static string RepoPath(params string[] segments)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "Mina.slnx")))
            {
                return Path.Combine([directory.FullName, .. segments]);
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate the repository root.");
    }
}

/// <summary>Signs a request in as the identity named in X-Test-* headers.</summary>
public sealed class HeaderAuthHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string SchemeName = "UiTest";

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue("X-Test-Oid", out var oid) || string.IsNullOrWhiteSpace(oid))
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        var claims = new List<Claim>
        {
            new("oid", oid.ToString()),
            new("preferred_username", Request.Headers["X-Test-Upn"].FirstOrDefault() ?? $"{oid}@fiaumalta.org"),
        };

        var roles = Request.Headers["X-Test-Roles"].FirstOrDefault();
        if (!string.IsNullOrEmpty(roles))
        {
            claims.AddRange(roles.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(role => new Claim("roles", role)));
        }

        var identity = new ClaimsIdentity(claims, SchemeName, "preferred_username", "roles");
        return Task.FromResult(AuthenticateResult.Success(
            new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName)));
    }
}
