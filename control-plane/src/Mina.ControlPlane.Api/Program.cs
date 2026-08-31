// Mina control-plane API (M2-2): Entra-authenticated session issuance, renewal and termination,
// region policy, and CSR-based session-certificate signing. Persistence is in-memory and the CA
// is an ephemeral development CA — both are labelled placeholders swapped for Azure SQL and a
// Key Vault-backed CA in later milestones.

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.Identity.Web;
using Mina.ControlPlane.Api.Configuration;
using Mina.ControlPlane.Api.Infrastructure;
using Mina.ControlPlane.Api.Sessions;
using Mina.ControlPlane.Application.Sessions;
using Mina.ControlPlane.Domain.Regions;
using Mina.ControlPlane.Domain.Sessions;
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
builder.Services.AddAuthorizationBuilder()
    .AddPolicy(SessionEndpoints.AnalystPolicy, policy => policy.RequireRole(analystRole));

// Domain/application services.
builder.Services.AddSingleton<ISessionRepository, InMemorySessionRepository>();
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

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/healthz", () => Results.Ok(new { status = "ok", component = "mina-control-plane-api" }))
    .AllowAnonymous();
app.MapMinaSessionEndpoints();

app.Run();

/// <summary>Exposed so the integration test host (WebApplicationFactory) can bootstrap the app.</summary>
public partial class Program;
