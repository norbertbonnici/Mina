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
using Mina.ControlPlane.Application.Regions;
using Mina.ControlPlane.Application.Sessions;
using Mina.ControlPlane.Application.Configuration;
using Mina.ControlPlane.Application.SensitiveSessions;
using Mina.ControlPlane.Application.Telemetry;
using Mina.ControlPlane.Domain.Regions;
using Mina.ControlPlane.Domain;
using Mina.ControlPlane.Domain.Audit;
using Mina.ControlPlane.Domain.SensitiveSessions;
using Mina.ControlPlane.Domain.Sessions;
using Mina.ControlPlane.Domain.Telemetry;
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
var telemetryViewerRole = builder.Configuration["Mina:Telemetry:ViewerRole"] ?? "Mina.TelemetryViewer";

builder.Services.AddManagementUi(approverRole, adminRole, telemetryViewerRole);
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
    builder.Services.AddSingleton<IRegionChangeRequestRepository, InMemoryRegionChangeRequestRepository>();
    builder.Services.AddSingleton<IUnitOfWork, InMemoryUnitOfWork>();
    builder.Services.AddSingleton<IAuditEventStore, InMemoryAuditEventStore>();
    builder.Services.AddSingleton<InMemoryTelemetryRepository>();
    builder.Services.AddSingleton<ITelemetryRepository>(sp => sp.GetRequiredService<InMemoryTelemetryRepository>());
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

// The audit trail screen (M3-2's own remaining item, unblocked once M3-3's store existed).
// Reading it is itself a privileged operation (AuditEndpoints' own remark) -- AuditReviewService
// writes audit_trail_viewed on every query, the same discipline BrowsingDataReviewService already
// applies below to telemetry_viewed.
builder.Services.AddScoped<AuditReviewService>();

// Region administration (ADR-0008 Option C, M3-2's other remaining item) -- captures and audits
// intent only. Mina:Regions:Approved/Active stay entirely IaC-owned; this service never writes
// them, only records who asked for a change and, later, who confirmed the reviewed deploy actually
// applied it.
builder.Services.AddOptions<RegionChangeRequestOptions>()
    .Bind(builder.Configuration.GetSection(RegionChangeRequestOptions.Section));
builder.Services.AddScoped<RegionChangeRequestService>();

// Expiry terminates a session, and that is a session-lifecycle event (session_revoked, High) as
// well as a suppression one. Registering the null sink here would repeat the mistake this UI was
// already caught making with the suppression sink: decisions made in the UI going unrecorded.
builder.Services.AddScoped<ISessionAuditSink, PersistentSessionAuditSink>();
builder.Services.AddScoped<SensitiveSessionService>();

// Browsing-data review (M3-8, threat N10): reading C3 hostname telemetry from this screen must
// reach the audit chain the same way every other decision here does, and the empty configuration
// below (Mina:ManagementUi:OfficeHours unset) is a supported, logged state — flagging stays off
// rather than guessing at a definition of "office hours" nobody has approved, the same posture
// TelemetryRetentionOptions already takes for how long C3 is kept.
builder.Services.AddOptions<OfficeHoursOptions>()
    .Bind(builder.Configuration.GetSection(OfficeHoursOptions.Section))
    .Validate(o => !o.Validate().Any(), $"Invalid {OfficeHoursOptions.Section} configuration.")
    .ValidateOnStart();
builder.Services.AddScoped<ITelemetryAuditSink, PersistentTelemetryAuditSink>();
builder.Services.AddScoped<BrowsingDataReviewService>();

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

if (!app.Services.GetRequiredService<IOptions<OfficeHoursOptions>>().Value.IsConfigured)
{
    UiStartupLog.OfficeHoursFlaggingDisabled(app.Logger, OfficeHoursOptions.Section);
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
