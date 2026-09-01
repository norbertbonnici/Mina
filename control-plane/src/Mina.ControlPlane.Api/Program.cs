// Mina control-plane API: Entra-authenticated session issuance, renewal and termination, region
// policy, CSR-based session-certificate signing, and the manager-approved suppression workflow.
//
// Sessions and approvals persist to Azure SQL when a connection string is configured, otherwise to
// an in-memory store for local development (warned about at startup). The issuing CA is still the
// ephemeral development CA — the Key Vault-backed provider is M2-2c and needs the Azure subscription.

using Microsoft.AspNetCore.Authentication.JwtBearer;
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
using Mina.ControlPlane.Persistence;
using Mina.ControlPlane.Pki;
using Mina.Observability;

var builder = WebApplication.CreateBuilder(args);

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
builder.Services.AddHostedService<SensitiveSessionExpiryService>();

// Egress-node interface: session allowlist and hostname telemetry ingest (M3-4).
builder.Services.AddScoped<ITelemetryAuditSink, PersistentTelemetryAuditSink>();
builder.Services.AddScoped<TelemetryIngestService>();
builder.Services.AddScoped<NodeDirectoryService>();

// Audit chain: durable, append-only, hash-linked, and periodically anchored to write-once storage.
builder.Services.AddScoped<AuditWriter>();
builder.Services.AddScoped<AuditChainVerifier>();
builder.Services.AddScoped<AuditAnchorVerifier>();
builder.Services.AddScoped<AuditExportService>();
builder.Services.AddSingleton<IAuditExportSink>(_ => new FileSystemAuditExportSink(
    builder.Configuration["Mina:Audit:ExportPath"]
    ?? Path.Combine(AppContext.BaseDirectory, "audit-exports"),
    builder.Configuration[$"{AuditOptions.Section}:Environment"] ?? "dev"));
builder.Services.AddHostedService<AuditExportBackgroundService>();

var app = builder.Build();

if (usingInMemoryStore)
{
    StartupLog.UsingInMemorySessionStore(app.Logger);
}

StartupLog.UsingDevelopmentCertificateAuthority(app.Logger);

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/healthz", () => Results.Ok(new { status = "ok", component = "mina-control-plane-api" }))
    .AllowAnonymous();
app.MapMinaSessionEndpoints();
app.MapMinaSensitiveSessionEndpoints();
app.MapMinaNodeEndpoints();
app.MapMinaAuditEndpoints();

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
