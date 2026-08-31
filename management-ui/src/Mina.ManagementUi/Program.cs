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

using Microsoft.Extensions.Options;
using Mina.ControlPlane.Application.SensitiveSessions;
using Mina.ControlPlane.Domain.Regions;
using Mina.ControlPlane.Domain.SensitiveSessions;
using Mina.ControlPlane.Domain.Sessions;
using Mina.ControlPlane.Persistence;
using Mina.ManagementUi.Infrastructure;

var builder = WebApplication.CreateBuilder(args);

var approverRole = builder.Configuration["Mina:SensitiveSession:ApproverRole"] ?? "Mina.Approver";
var adminRole = builder.Configuration["Mina:Ui:AdminRole"] ?? "Mina.Admin";

builder.Services.AddManagementUi(approverRole, adminRole);
builder.Services.AddManagementUiAuthentication(builder.Configuration, builder.Environment);

builder.Services.Configure<MinaUiRegionOptions>(builder.Configuration.GetSection("Mina:Regions"));
builder.Services.Configure<SensitiveSessionOptions>(builder.Configuration.GetSection("Mina:SensitiveSession"));

builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton(sp =>
{
    var regions = sp.GetRequiredService<IOptions<MinaUiRegionOptions>>().Value;
    return new RegionPolicy(regions.Approved, regions.Active);
});

// Same store as the API: Azure SQL when configured, otherwise in-memory for local review.
var connectionString = builder.Configuration.GetConnectionString("MinaDb");
var usingInMemoryStore = string.IsNullOrWhiteSpace(connectionString);
if (usingInMemoryStore)
{
    builder.Services.AddSingleton<InMemorySessionRepository>();
    builder.Services.AddSingleton<ISessionRepository>(sp => sp.GetRequiredService<InMemorySessionRepository>());
    builder.Services.AddSingleton<ISessionQueries>(sp => sp.GetRequiredService<InMemorySessionRepository>());
    builder.Services.AddSingleton<ISensitiveSessionRepository, InMemorySensitiveSessionRepository>();
}
else
{
    builder.Services.AddMinaSqlPersistence(connectionString!);
    builder.Services.AddScoped<ISessionQueries>(sp => (EfSessionRepository)sp.GetRequiredService<ISessionRepository>());
}

builder.Services.AddSingleton<ISensitiveSessionAuditSink, NullSensitiveSessionAuditSink>();
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

app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

app.MapManagementUi();

app.Run();

/// <summary>Exposed so the integration test host can bootstrap the application.</summary>
public partial class Program;
