// Mina control-plane API: Entra-authenticated session issuance, renewal and termination, region
// policy, CSR-based session-certificate signing, and the manager-approved suppression workflow.
//
// Since ADR-0006 this runs on premises in the FIAU Proxmox cluster, not on Azure App Service.
// Sessions and approvals persist to SQL Server (Arc-enabled, so Entra authentication works with no
// stored credential) when a connection string is configured. The in-memory stores, the ephemeral CA
// and the filesystem audit sink remain available as development stand-ins, but a host that is not
// Development now refuses to start on one rather than warning and carrying on: configuration is
// hand-delivered to a VM now, so a missing setting is a likely mistake rather than an impossible
// one. The Key Vault-backed CA is still M2-2c.

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Options;
using Microsoft.Identity.Web;
using Mina.ControlPlane.Api.Configuration;
using Mina.ControlPlane.Api.Infrastructure;
using Mina.ControlPlane.Api.Sessions;
using Mina.ControlPlane.Application.Audit;
using Mina.ControlPlane.Application.Configuration;
using Mina.ControlPlane.Application.SensitiveSessions;
using Mina.ControlPlane.Application.Sessions;
using Mina.ControlPlane.Application.Telemetry;
using Mina.ControlPlane.Domain;
using Mina.ControlPlane.Domain.Audit;
using Mina.ControlPlane.Domain.Regions;
using Mina.ControlPlane.Domain.SensitiveSessions;
using Mina.ControlPlane.Domain.Sessions;
using Mina.ControlPlane.Domain.Telemetry;
using Mina.ControlPlane.Hosting;
using Mina.ControlPlane.Persistence;
using Mina.ControlPlane.Pki;
using Mina.Observability;

var builder = WebApplication.CreateBuilder(args);

// Behind the DMZ reverse proxy the platform sees plain HTTP unless it is told otherwise (ADR-0006).
builder.Services.Configure<ForwardedHeadersOptions>(
    options => HostingGuard.ConfigureForwardedHeaders(options, builder.Configuration));

var allowDevelopmentFallbacks = HostingGuard.DevelopmentFallbacksAllowed(
    builder.Configuration, builder.Environment);

// ADR-0006 constraint 1: the node-facing endpoint is published to the internet, so the management
// surface must not be reachable there even if the DMZ proxy is misconfigured. Two Kestrel listeners,
// and every endpoint declares which one it belongs to.
var listenersSeparated = builder.ConfigureMinaListeners();

// Operational telemetry to SigNoz. The scrub processors are part of this wiring, not optional.
builder.Services.AddMinaObservability(builder.Configuration);

// Bound and validated at startup: a bad policy value must stop the host, not surface later as a
// database error or as a workflow that silently refuses everything.
builder.Services.AddValidatedMinaOptions(builder.Configuration);
builder.Services.Configure<MinaRegionOptions>(builder.Configuration.GetSection(MinaRegionOptions.Section));
builder.Services.Configure<MinaEgressOptions>(builder.Configuration.GetSection(MinaEgressOptions.Section));

// Entra token validation (Conditional Access / device compliance are enforced at Entra).
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddMicrosoftIdentityWebApi(builder.Configuration.GetSection("AzureAd"));

var analystRole = builder.Configuration["Mina:Session:AnalystRole"] ?? "Mina.Analyst";
var approverRole = builder.Configuration["Mina:SensitiveSession:ApproverRole"] ?? "Mina.Approver";
var nodeRole = builder.Configuration["Mina:Node:Role"] ?? "Mina.Node";
var adminRole = builder.Configuration["Mina:Audit:AdminRole"] ?? "Mina.Admin";
builder.Services.AddAuthorizationBuilder()
    .AddPolicy(SessionEndpoints.AnalystPolicy, policy => policy.RequireRole(analystRole))
    .AddPolicy(SensitiveSessionEndpoints.ApproverPolicy, policy => policy.RequireRole(approverRole))
    .AddPolicy(NodeEndpoints.NodePolicy, policy => policy.RequireRole(nodeRole))
    .AddPolicy(AuditEndpoints.AdminPolicy, policy => policy.RequireRole(adminRole));

// Session store: Azure SQL when configured, otherwise an in-memory store for local development
// (warned about at startup). Migrations are applied by the deployment pipeline, never on startup —
// schema changes stay a deliberate, reviewable step.
var sessionConnectionString = builder.Configuration.GetConnectionString("MinaDb");
var usingInMemoryStore = string.IsNullOrWhiteSpace(sessionConnectionString);
if (usingInMemoryStore)
{
    HostingGuard.RequireExplicitFallback(
        allowDevelopmentFallbacks,
        "in-memory session, approval, telemetry and audit stores that lose everything on restart",
        "ConnectionStrings:MinaDb");

    builder.Services.AddSingleton<InMemorySessionRepository>();
    builder.Services.AddSingleton<ISessionRepository>(sp => sp.GetRequiredService<InMemorySessionRepository>());
    builder.Services.AddSingleton<ISessionQueries>(sp => sp.GetRequiredService<InMemorySessionRepository>());
    builder.Services.AddSingleton<ISensitiveSessionRepository, InMemorySensitiveSessionRepository>();
    builder.Services.AddSingleton<ITelemetryRepository, InMemoryTelemetryRepository>();
    builder.Services.AddSingleton<InMemoryAuditEventStore>();
    builder.Services.AddSingleton<IUnitOfWork, InMemoryUnitOfWork>();
    builder.Services.AddSingleton<IAuditEventStore>(sp => new LoggingAuditEventStore(
        sp.GetRequiredService<InMemoryAuditEventStore>(),
        sp.GetRequiredService<ILogger<LoggingAuditEventStore>>()));
}
else
{
    builder.Services.AddMinaSqlPersistence(sessionConnectionString!);
    builder.Services.AddScoped<ISessionQueries>(sp => (EfSessionRepository)sp.GetRequiredService<ISessionRepository>());
    builder.Services.AddScoped<EfAuditEventStore>();
    builder.Services.AddScoped<IAuditEventStore>(sp => new LoggingAuditEventStore(
        sp.GetRequiredService<EfAuditEventStore>(),
        sp.GetRequiredService<ILogger<LoggingAuditEventStore>>()));
}

builder.Services.AddSingleton<IEgressDirectory, ConfiguredEgressDirectory>();
builder.Services.AddScoped<ISessionAuditSink, PersistentSessionAuditSink>();
builder.Services.AddSingleton(TimeProvider.System);
HostingGuard.RequireExplicitFallback(
    allowDevelopmentFallbacks || listenersSeparated,
    "a single listener serving the node API and the management surface together, so publishing it "
    + "to the DMZ would publish the approvals UI and the audit read API with it",
    $"{MinaListenerOptions.Section}:NodePort and :ManagementPort");

// The signing key for every session certificate. The Key Vault-backed provider is M2-2c; until it
// exists there is no production-capable CA, and starting without one would mint session
// certificates from a key that is regenerated on every restart.
HostingGuard.RequireExplicitFallback(
    allowDevelopmentFallbacks,
    "an ephemeral in-process certificate authority whose key is regenerated on every restart",
    "the Key Vault-backed certificate authority (backlog M2-2c)");
builder.Services.AddSingleton<ICertificateAuthorityProvider, DevelopmentCertificateAuthorityProvider>();

builder.Services.AddSingleton(sp =>
{
    var regions = sp.GetRequiredService<IOptions<MinaRegionOptions>>().Value;
    return new RegionPolicy(regions.Approved, regions.Active);
});

builder.Services.AddSingleton(sp =>
{
    var ttl = sp.GetRequiredService<IOptions<SessionServiceOptions>>().Value.LeaseTtl;
    var authority = sp.GetRequiredService<ICertificateAuthorityProvider>().GetAuthority();
    return new SessionCertificateIssuer(authority, new SessionCertificatePolicy(ttl));
});

builder.Services.AddScoped<SessionService>();

// Sensitive-session (suppression) workflow — ADR-0003. Options bound above.
builder.Services.AddScoped<ISensitiveSessionAuditSink, PersistentSensitiveSessionAuditSink>();
builder.Services.AddScoped<SensitiveSessionService>();
// Timer-driven work. Both timers run in every process, which was harmless on a single App Service
// instance and is a decision on an on-premises HA pair — see HostingGuard.RunBackgroundServicesKey.
var runBackgroundServices = HostingGuard.BackgroundServicesEnabled(builder.Configuration);
if (runBackgroundServices)
{
    builder.Services.AddHostedService<SensitiveSessionExpiryService>();
}

// Egress-node interface: session allowlist and hostname telemetry ingest (M3-4).
builder.Services.AddScoped<ITelemetryAuditSink, PersistentTelemetryAuditSink>();
builder.Services.AddScoped<TelemetryIngestService>();
builder.Services.AddScoped<NodeDirectoryService>();

// Audit chain: durable, append-only, hash-linked, and periodically anchored to write-once storage.
builder.Services.AddScoped<AuditWriter>();
builder.Services.AddScoped<AuditChainVerifier>();
builder.Services.AddScoped<AuditAnchorVerifier>();
builder.Services.AddScoped<AuditExportService>();
// Audit anchors must land in storage that can refuse an overwrite. A filesystem cannot, so the
// tamper-evidence is only as good as the administrator who owns the disk (ADR-0006 keeps the real
// anchors in Azure immutable blob storage; that sink is still to be written).
HostingGuard.RequireExplicitFallback(
    allowDevelopmentFallbacks,
    "a filesystem audit export sink, which cannot enforce write-once and so anchors nothing",
    "Mina:Audit:ExportContainerUri (Azure immutable blob storage)");
builder.Services.AddSingleton<IAuditExportSink>(_ => new FileSystemAuditExportSink(
    builder.Configuration["Mina:Audit:ExportPath"]
    ?? Path.Combine(AppContext.BaseDirectory, "audit-exports"),
    builder.Configuration[$"{AuditOptions.Section}:Environment"] ?? "dev"));
if (runBackgroundServices)
{
    builder.Services.AddHostedService<AuditExportBackgroundService>();
}

var app = builder.Build();

// Before authentication: the scheme and client address every later decision uses come from here.
app.UseForwardedHeaders();

if (usingInMemoryStore)
{
    StartupLog.UsingInMemorySessionStore(app.Logger);
}

StartupLog.UsingDevelopmentCertificateAuthority(app.Logger);

if (!runBackgroundServices)
{
    StartupLog.BackgroundServicesDisabled(app.Logger);
}

// Routing first so the endpoint's listener metadata is known; the separation check before
// authentication so a request on the wrong listener gets a plain 404 rather than a challenge.
app.UseRouting();
app.UseMinaListenerSeparation();
app.UseAuthentication();
app.UseAuthorization();

// No listener declared: the health probe answers on both, so the DMZ proxy and the corporate load
// balancer can each check the listener they front.
app.MapGet("/healthz", () => Results.Ok(new { status = "ok", component = "mina-control-plane-api" }))
    .AllowAnonymous();

// Published to the internet from the FIAU DMZ: the egress nodes' allowlist and telemetry ingest,
// and nothing else.
app.MapMinaNodeEndpoints(MinaListener.Node);

// Corporate-facing only. The analyst session API belongs here because the endpoint agent runs on a
// corporate-managed workstation on the corporate network; if analysts ever need Mina from outside
// that network, publishing these is a separate exposure decision and not something to inherit by
// accident.
app.MapMinaSessionEndpoints(MinaListener.Management);
app.MapMinaSensitiveSessionEndpoints(MinaListener.Management);
app.MapMinaAuditEndpoints(MinaListener.Management);

app.Run();

/// <summary>Exposed so the integration test host (WebApplicationFactory) can bootstrap the app.</summary>
public partial class Program;

namespace Mina.ControlPlane.Api
{
    /// <summary>
    /// Names this assembly for test hosts. Referenced instead of <c>Program</c> because
    /// Microsoft.AspNetCore.Mvc.Testing makes referenced projects' internals visible to the test
    /// assembly, so a bare <c>Program</c> can collide with another entry point's.
    /// </summary>
    public sealed class ControlPlaneApiEntryPoint;
}
