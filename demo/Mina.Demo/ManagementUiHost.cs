using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Mina.ControlPlane.Application.SensitiveSessions;
using Mina.ControlPlane.Application.Sessions;
using Mina.ControlPlane.Domain;
using Mina.ControlPlane.Domain.Regions;
using Mina.ControlPlane.Domain.SensitiveSessions;
using Mina.ControlPlane.Domain.Sessions;
using Mina.ControlPlane.Persistence;
using Mina.ManagementUi.Infrastructure;
using Mina.TestSupport;

namespace Mina.Demo;

/// <summary>
/// Runs the management UI on a real port so a browser can reach it, against the same in-memory
/// stores the demo's control-plane API is using. It composes the UI from the shipping
/// <see cref="ManagementUiComposition"/> extensions, so the screens, policies and decision
/// endpoints are the real ones — only sign-in is substituted, and only inside this demo process.
/// </summary>
internal static class ManagementUiHost
{
    public static async Task<WebApplication> StartAsync(
        int port,
        ISessionRepository sessions,
        ISessionQueries sessionQueries,
        ISensitiveSessionRepository requests,
        IReadOnlyCollection<string> approvedRegions,
        IReadOnlyCollection<string> activeRegions,
        string approverUpn)
    {
        // The web root must be supplied when the builder is created; assigning it afterwards leaves
        // the static-file provider pointing at the demo's own directory.
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            WebRootPath = RepoRoot.Path("management-ui", "src", "Mina.ManagementUi", "wwwroot"),
        });
        builder.WebHost.UseUrls($"http://127.0.0.1:{port}");
        builder.Logging.SetMinimumLevel(LogLevel.Warning);

        builder.Services.AddManagementUi("Mina.Approver", "Mina.Admin", "Mina.TelemetryViewer");

        // Demo sign-in: every visitor is the approver. Confined to this process — the shipping UI
        // refuses its development sign-in outside a Development host.
        builder.Services.Configure<DevSignInOptions>(options =>
        {
            options.Enabled = true;
            options.ObjectId = "oid-demo-approver";
            options.UserPrincipalName = approverUpn;
            options.Roles = ["Mina.Approver"];
        });
        builder.Services.AddAuthentication(DevSignInAuthHandler.SchemeName)
            .AddScheme<AuthenticationSchemeOptions, DevSignInAuthHandler>(
                DevSignInAuthHandler.SchemeName, _ => { });

        builder.Services.AddSingleton(TimeProvider.System);
        builder.Services.AddSingleton(new RegionPolicy(approvedRegions, activeRegions));
        builder.Services.AddSingleton(sessions);
        builder.Services.AddSingleton(sessionQueries);
        builder.Services.AddSingleton(requests);
        builder.Services.AddSingleton<ISensitiveSessionAuditSink, NullSensitiveSessionAuditSink>();
        // Same substitution as the sensitive-session sink above: the demo's audit trail of record
        // is the control-plane API's own sinks (visible as the info: audit ... lines on the
        // console), not this UI's own service instance. Without these two, SensitiveSessionService
        // fails to activate at all — its constructor has required them since the D-06a
        // expiry-terminates-the-session change, and this host was never updated for it.
        builder.Services.AddSingleton<ISessionAuditSink, NullSessionAuditSink>();
        builder.Services.AddSingleton<IUnitOfWork, InMemoryUnitOfWork>();
        builder.Services.Configure<SensitiveSessionOptions>(_ => { });
        builder.Services.AddScoped<SensitiveSessionService>();

        var app = builder.Build();
        app.UseStaticFiles();
        app.UseAuthentication();
        app.UseAuthorization();
        app.UseAntiforgery();
        app.MapManagementUi();

        await app.StartAsync().ConfigureAwait(false);
        return app;
    }
}
