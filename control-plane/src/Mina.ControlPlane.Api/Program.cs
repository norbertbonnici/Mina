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
using Mina.ControlPlane.Application.SensitiveSessions;
using Mina.ControlPlane.Application.Sessions;
using Mina.ControlPlane.Domain.Regions;
using Mina.ControlPlane.Domain.SensitiveSessions;
using Mina.ControlPlane.Domain.Sessions;
using Mina.ControlPlane.Persistence;
using Mina.ControlPlane.Pki;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<SessionServiceOptions>(builder.Configuration.GetSection("Mina:Session"));
builder.Services.Configure<MinaRegionOptions>(builder.Configuration.GetSection(MinaRegionOptions.Section));
builder.Services.Configure<MinaEgressOptions>(builder.Configuration.GetSection(MinaEgressOptions.Section));

// Entra token validation (Conditional Access / device compliance are enforced at Entra).
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddMicrosoftIdentityWebApi(builder.Configuration.GetSection("AzureAd"));

var analystRole = builder.Configuration["Mina:Session:AnalystRole"] ?? "Mina.Analyst";
var approverRole = builder.Configuration["Mina:SensitiveSession:ApproverRole"] ?? "Mina.Approver";
builder.Services.AddAuthorizationBuilder()
    .AddPolicy(SessionEndpoints.AnalystPolicy, policy => policy.RequireRole(analystRole))
    .AddPolicy(SensitiveSessionEndpoints.ApproverPolicy, policy => policy.RequireRole(approverRole));

// Session store: Azure SQL when configured, otherwise an in-memory store for local development
// (warned about at startup). Migrations are applied by the deployment pipeline, never on startup —
// schema changes stay a deliberate, reviewable step.
var sessionConnectionString = builder.Configuration.GetConnectionString("MinaDb");
var usingInMemoryStore = string.IsNullOrWhiteSpace(sessionConnectionString);
if (usingInMemoryStore)
{
    builder.Services.AddSingleton<ISessionRepository, InMemorySessionRepository>();
    builder.Services.AddSingleton<ISensitiveSessionRepository, InMemorySensitiveSessionRepository>();
}
else
{
    builder.Services.AddMinaSqlPersistence(sessionConnectionString!);
}

builder.Services.AddSingleton<IEgressDirectory, ConfiguredEgressDirectory>();
builder.Services.AddSingleton<ISessionAuditSink, LoggingSessionAuditSink>();
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

// Sensitive-session (suppression) workflow — ADR-0003.
builder.Services.Configure<SensitiveSessionOptions>(builder.Configuration.GetSection("Mina:SensitiveSession"));
builder.Services.AddSingleton<ISensitiveSessionAuditSink, LoggingSensitiveSessionAuditSink>();
builder.Services.AddScoped<SensitiveSessionService>();
builder.Services.AddHostedService<SensitiveSessionExpiryService>();

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

app.Run();

/// <summary>Exposed so the integration test host (WebApplicationFactory) can bootstrap the app.</summary>
public partial class Program;
