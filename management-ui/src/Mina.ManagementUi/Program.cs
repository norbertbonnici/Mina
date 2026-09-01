// Mina management UI (M3-2): the approvals queue, sessions and platform overview for managers and
// platform administrators (FR-013).
//
// Rendering is static server-side throughout — an admin console gains nothing from a persistent
// circuit, and plain request/response keeps every screen simple to reason about and to test.
//
// The UI calls the control-plane application services directly against the same database as the
// API, rather than over HTTP. Both are trusted server-side halves of the control plane, and the
// authorisation rules live in the application services, so they are enforced identically whichever
// front door a request arrives through.

using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Options;
using Mina.ControlPlane.Application.Audit;
using Mina.ControlPlane.Application.Sessions;
using Mina.ControlPlane.Application.Configuration;
using Mina.ControlPlane.Application.SensitiveSessions;
using Mina.ControlPlane.Domain.Regions;
using Mina.ControlPlane.Domain;
using Mina.ControlPlane.Domain.Audit;
using Mina.ControlPlane.Domain.SensitiveSessions;
using Mina.ControlPlane.Domain.Sessions;
using Mina.ControlPlane.Hosting;
using Mina.ControlPlane.Persistence;
using Mina.ManagementUi.Infrastructure;

var builder = WebApplication.CreateBuilder(args);

// On premises (ADR-0006) this sits behind the DMZ reverse proxy, which terminates TLS and manages
// nothing else. Both of these were previously supplied by App Service.
builder.Services.Configure<ForwardedHeadersOptions>(
    options => HostingGuard.ConfigureForwardedHeaders(options, builder.Configuration));
builder.Services.AddMinaDataProtection(builder.Configuration, builder.Environment);

var allowDevelopmentFallbacks = HostingGuard.DevelopmentFallbacksAllowed(
    builder.Configuration, builder.Environment);

var approverRole = builder.Configuration["Mina:SensitiveSession:ApproverRole"] ?? "Mina.Approver";
var adminRole = builder.Configuration["Mina:Ui:AdminRole"] ?? "Mina.Admin";

builder.Services.AddManagementUi(approverRole, adminRole);
builder.Services.AddManagementUiAuthentication(builder.Configuration, builder.Environment);

builder.Services.Configure<MinaUiRegionOptions>(builder.Configuration.GetSection("Mina:Regions"));

builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton(sp =>
{
    var regions = sp.GetRequiredService<IOptions<MinaUiRegionOptions>>().Value;
    return new RegionPolicy(regions.Approved, regions.Active);
});

// The same store the API uses: on-premises SQL Server when configured (ADR-0006), otherwise
// in-memory for local review — and only when that stand-in has been explicitly permitted. An
// approvals screen backed by a store that empties on restart is worse than one that will not start.
var connectionString = builder.Configuration.GetConnectionString("MinaDb");
var usingInMemoryStore = string.IsNullOrWhiteSpace(connectionString);
if (usingInMemoryStore)
{
    HostingGuard.RequireExplicitFallback(
        allowDevelopmentFallbacks,
        "in-memory approval and audit stores that lose every decision on restart",
        "ConnectionStrings:MinaDb");

    builder.Services.AddSingleton<InMemorySessionRepository>();
    builder.Services.AddSingleton<ISessionRepository>(sp => sp.GetRequiredService<InMemorySessionRepository>());
    builder.Services.AddSingleton<ISessionQueries>(sp => sp.GetRequiredService<InMemorySessionRepository>());
    builder.Services.AddSingleton<ISensitiveSessionRepository, InMemorySensitiveSessionRepository>();
    builder.Services.AddSingleton<IUnitOfWork, InMemoryUnitOfWork>();
    builder.Services.AddSingleton<IAuditEventStore, InMemoryAuditEventStore>();
}
else
{
    builder.Services.AddMinaSqlPersistence(connectionString!);
    builder.Services.AddScoped<ISessionQueries>(sp => (EfSessionRepository)sp.GetRequiredService<ISessionRepository>());
}

// Decisions taken here are approvals: they must reach the audit chain exactly as they do over the
// API. Using a null sink meant every approval made in this UI — the way approvals are actually
// made — went unrecorded, which ADR-0003 does not permit.
builder.Services.AddValidatedMinaOptions(builder.Configuration);
builder.Services.AddScoped<AuditWriter>();
builder.Services.AddScoped<ISensitiveSessionAuditSink, PersistentSensitiveSessionAuditSink>();

// Expiry terminates a session, and that is a session-lifecycle event (session_revoked, High) as
// well as a suppression one. Registering the null sink here would repeat the mistake this UI was
// already caught making with the suppression sink: decisions made in the UI going unrecorded.
builder.Services.AddScoped<ISessionAuditSink, PersistentSessionAuditSink>();
builder.Services.AddScoped<SensitiveSessionService>();

var app = builder.Build();

if (usingInMemoryStore)
{
    UiStartupLog.UsingInMemoryStore(app.Logger);
}

var devSignIn = app.Services.GetRequiredService<IOptions<DevSignInOptions>>().Value;
if (devSignIn.Enabled)
{
    UiStartupLog.UsingDevelopmentSignIn(app.Logger, devSignIn.UserPrincipalName);
}

app.UseForwardedHeaders();
app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

app.MapManagementUi();

app.Run();

/// <summary>Exposed so the integration test host can bootstrap the application.</summary>
public partial class Program;
