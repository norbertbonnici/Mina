// Mina control-plane API: Entra-authenticated session issuance, renewal and termination, region
// policy, CSR-based session-certificate signing, and the manager-approved suppression workflow.
//
// Since ADR-0006 this runs on premises in the on-premises Proxmox cluster, not on Azure App Service.
// Sessions and approvals persist to SQL Server (Arc-enabled, so Entra authentication works with no
// stored credential) when a connection string is configured. The in-memory stores, the ephemeral CA
// and the filesystem audit sink remain available as development stand-ins, but a host that is not
// Development now refuses to start on one rather than warning and carrying on: configuration is
// hand-delivered to a VM now, so a missing setting is a likely mistake rather than an impossible
// one. Configure Mina:Pki:KeyVaultUri and the CA's signing key is one Key Vault holds and will not
// export (M2-2c).

using Azure.Identity;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
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
using Mina.ControlPlane.Domain.Coordination;
using Mina.ControlPlane.Domain.Regions;
using Mina.ControlPlane.Domain.SensitiveSessions;
using Mina.ControlPlane.Domain.Sessions;
using Mina.ControlPlane.Domain.Telemetry;
using Mina.ControlPlane.Hosting;
using Mina.ControlPlane.KeyVault;
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

// The five role-name settings become the five route policies. Read when AuthorizationOptions is
// first resolved rather than inline here: inline reads run before a test host's configuration
// overrides are applied, which meant the policies silently kept their defaults under test and the
// role names were never actually exercised as configuration (found by M2-6's drift tests: renaming
// a role moved nothing). Production configuration is complete before either point, so this changes
// nothing there; it makes "the role names are configuration" a tested property instead of a claim.
builder.Services.AddAuthorization();
builder.Services.AddOptions<AuthorizationOptions>().Configure<IConfiguration>((options, configuration) =>
{
    var analystRole = configuration["Mina:Session:AnalystRole"] ?? "Mina.Analyst";
    var approverRole = configuration["Mina:SensitiveSession:ApproverRole"] ?? "Mina.Approver";
    var nodeRole = configuration["Mina:Node:Role"] ?? "Mina.Node";
    var adminRole = configuration["Mina:Audit:AdminRole"] ?? "Mina.Admin";
    var telemetryViewerRole = configuration["Mina:Telemetry:ViewerRole"] ?? "Mina.TelemetryViewer";
    options.AddPolicy(SessionEndpoints.AnalystPolicy, policy => policy.RequireRole(analystRole));
    options.AddPolicy(SensitiveSessionEndpoints.ApproverPolicy, policy => policy.RequireRole(approverRole));
    options.AddPolicy(NodeEndpoints.NodePolicy, policy => policy.RequireRole(nodeRole));
    options.AddPolicy(AuditEndpoints.AdminPolicy, policy => policy.RequireRole(adminRole));
    options.AddPolicy(BrowsingDataEndpoints.TelemetryViewerPolicy, policy => policy.RequireRole(telemetryViewerRole));
});

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
    builder.Services.AddSingleton<IBackgroundLeaseStore, AlwaysGrantedLeaseStore>();
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
    listenersSeparated || HostingGuard.SingleListenerAllowed(builder.Configuration, builder.Environment),
    "a single listener serving the node API and the management surface together, so publishing it "
    + "to the DMZ would publish the approvals UI and the audit read API with it",
    $"{MinaListenerOptions.Section}:NodePort and :ManagementPort");

// The signing key for every session certificate (M2-2c). Configured: Key Vault holds the key, this
// process holds only the certificate, and each issuance is a sign operation the vault performs and
// records. Unconfigured: an ephemeral in-process key that is regenerated on every restart, which a
// host that is not Development refuses to start on.
var pkiOptions = builder.Configuration.GetSection(MinaPkiOptions.Section).Get<MinaPkiOptions>()
    ?? new MinaPkiOptions();
if (pkiOptions.IsConfigured)
{
    var keyVaultCa = pkiOptions.ToKeyVaultOptions();
    builder.Services.AddSingleton<ICertificateAuthorityProvider>(
        _ => KeyVaultCertificateAuthorityProvider.Create(keyVaultCa, new DefaultAzureCredential()));
}
else
{
    HostingGuard.RequireExplicitFallback(
        allowDevelopmentFallbacks,
        "an ephemeral in-process certificate authority whose key is regenerated on every restart",
        $"{MinaPkiOptions.Section}:KeyVaultUri (the Key Vault-backed certificate authority)");
    builder.Services.AddSingleton<ICertificateAuthorityProvider, DevelopmentCertificateAuthorityProvider>();
}

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

// A node's own server certificate (M2-2d) — the same CA, a different leaf shape (serverAuth, no
// client-chosen TTL). Shares whichever ICertificateAuthorityProvider was registered above, Key
// Vault-backed or the Development stand-in.
builder.Services.AddSingleton(sp =>
{
    var authority = sp.GetRequiredService<ICertificateAuthorityProvider>().GetAuthority();
    return new NodeCertificateIssuer(authority, pkiOptions.NodeCertificateLifetime);
});

builder.Services.AddScoped<SessionService>();

// Sensitive-session (suppression) workflow — ADR-0003. Options bound above.
builder.Services.AddScoped<ISensitiveSessionAuditSink, PersistentSensitiveSessionAuditSink>();
builder.Services.AddScoped<SensitiveSessionService>();
// Timer-driven work. Every instance runs the two expiry sweeps: both are safe duplicated, because
// each item is handled in its own unit of work and the loser of a race gets a concurrency conflict
// it already handles. Deliberately not gated on a lease — expiring suppression on time is AC-011,
// and it must not stop because a lease could not be read.
builder.Services.AddHostedService<SensitiveSessionExpiryService>();
builder.Services.AddHostedService<SessionExpiryService>();

// Egress-node interface: session allowlist and hostname telemetry ingest (M3-4).
builder.Services.AddScoped<ITelemetryAuditSink, PersistentTelemetryAuditSink>();
builder.Services.AddScoped<TelemetryIngestService>();
builder.Services.AddScoped<NodeDirectoryService>();

// Browsing-data review (M3-8, threat N10). Off-hours flagging is unset by default, the same
// posture as TelemetryRetentionOptions below: an off-hours flag is a judgement about an analyst
// that must not start being made on a definition nobody approved.
builder.Services.AddOptions<OfficeHoursOptions>()
    .Bind(builder.Configuration.GetSection(OfficeHoursOptions.Section))
    .Validate(o => !o.Validate().Any(), $"Invalid {OfficeHoursOptions.Section} configuration.")
    .ValidateOnStart();
builder.Services.AddScoped<BrowsingDataReviewService>();

// C3 retention (M4-9). Off unless a period is configured: the operating value in
// LOGGING_AND_PRIVACY is a proposal awaiting DPO ratification, and deleting analyst records on an
// unratified number is its own failure. The service says which state it is in at startup.
builder.Services.AddOptions<TelemetryRetentionOptions>()
    .Bind(builder.Configuration.GetSection(TelemetryRetentionOptions.SectionName))
    .Validate(o => !o.Validate().Any(), "Invalid Mina:Telemetry:Retention configuration.")
    .ValidateOnStart();
builder.Services.AddScoped<TelemetryRetentionService>();
builder.Services.AddHostedService<TelemetryRetentionBackgroundService>();

// Audit chain: durable, append-only, hash-linked, and periodically anchored to write-once storage.
builder.Services.AddScoped<AuditWriter>();
builder.Services.AddScoped<AuditChainVerifier>();
builder.Services.AddScoped<AuditAnchorVerifier>();
builder.Services.AddScoped<AuditExportService>();
// Audit anchors must land in storage that can refuse an overwrite. A filesystem cannot, so the
// tamper-evidence is only as good as the administrator who owns the disk. Configured means Azure
// immutable blob storage (D-18, M4-19) — a delete or overwrite of a blob inside its retention
// window is refused by the storage service itself, even to the subscription owner.
var auditOptions = builder.Configuration.GetSection(AuditOptions.Section).Get<AuditOptions>()
    ?? new AuditOptions();
if (auditOptions.IsAzureExportConfigured)
{
    builder.Services.AddSingleton<IAuditExportSink>(_ => new AzureBlobAuditExportSink(
        new Uri(auditOptions.ExportContainerUri!),
        new Azure.Identity.DefaultAzureCredential(),
        auditOptions.Environment));
}
else
{
    HostingGuard.RequireExplicitFallback(
        allowDevelopmentFallbacks,
        "a filesystem audit export sink, which cannot enforce write-once and so anchors nothing",
        "Mina:Audit:ExportContainerUri (Azure immutable blob storage)");
    builder.Services.AddSingleton<IAuditExportSink>(_ => new FileSystemAuditExportSink(
        builder.Configuration["Mina:Audit:ExportPath"]
        ?? Path.Combine(AppContext.BaseDirectory, "audit-exports"),
        auditOptions.Environment));
}
// The export is the one that is not safe duplicated, so it takes a lease (M4-23). It runs in every
// instance; only the lease holder does the work.
builder.Services.AddHostedService<AuditExportBackgroundService>();

// Wazuh delivery (M3-5, AC-013). Off unless a delivery target is configured — the same "unset is
// safe" posture as TelemetryRetentionOptions/OfficeHoursOptions above, since a real path is
// environment-specific and unknown in dev/test.
builder.Services.AddOptions<WazuhDeliveryOptions>()
    .Bind(builder.Configuration.GetSection(WazuhDeliveryOptions.SectionName))
    .Validate(o => !o.Validate().Any(), $"Invalid {WazuhDeliveryOptions.SectionName} configuration.")
    .ValidateOnStart();
var wazuhOptions = builder.Configuration.GetSection(WazuhDeliveryOptions.SectionName).Get<WazuhDeliveryOptions>()
    ?? new WazuhDeliveryOptions();
if (wazuhOptions.IsConfigured)
{
    builder.Services.AddSingleton<IWazuhEventSink>(_ => new FileSystemWazuhEventSink(wazuhOptions.EventFilePath!));
}
else
{
    builder.Services.AddSingleton<IWazuhEventSink, NullWazuhEventSink>();
}

builder.Services.AddScoped<WazuhDeliveryService>();
// Not safe duplicated across instances -- two deliverers would double-append every line -- so it
// takes the same lease pattern as the audit export above, under its own lease name.
builder.Services.AddHostedService<WazuhDeliveryBackgroundService>();

var app = builder.Build();

// Before authentication: the scheme and client address every later decision uses come from here.
app.UseForwardedHeaders();

if (usingInMemoryStore)
{
    StartupLog.UsingInMemorySessionStore(app.Logger);
}

if (!app.Services.GetRequiredService<IOptions<OfficeHoursOptions>>().Value.IsConfigured)
{
    StartupLog.OfficeHoursFlaggingDisabled(app.Logger, OfficeHoursOptions.Section);
}

if (!app.Services.GetRequiredService<IOptions<WazuhDeliveryOptions>>().Value.IsConfigured)
{
    StartupLog.WazuhDeliveryDisabled(app.Logger, WazuhDeliveryOptions.SectionName);
}

// Resolving the provider is what reaches Key Vault, so doing it here rather than on the first
// session request is the difference between a host that refuses to start and one that starts and
// cannot issue a certificate. The subject and expiry go to the log because they are what an
// operator needs to tell one CA from another, and the only cheap check that the vault this host
// was pointed at is the one the nodes trust.
using (var caCertificate = app.Services.GetRequiredService<ICertificateAuthorityProvider>()
    .GetAuthority().PublicCertificate)
{
    if (pkiOptions.IsConfigured)
    {
        var subject = caCertificate.Subject;
        var expiry = caCertificate.NotAfter.ToUniversalTime();
        StartupLog.UsingKeyVaultCertificateAuthority(
            app.Logger, pkiOptions.KeyVaultUri!, subject, expiry);
    }
    else
    {
        StartupLog.UsingDevelopmentCertificateAuthority(app.Logger);
    }
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
    .AllowAnonymous()
    .AllowOnAnyListener();

// Published to the internet from the on-premises DMZ: the egress nodes' allowlist and telemetry ingest,
// and nothing else.
app.MapMinaNodeEndpoints(MinaListener.Node);

// Corporate-facing only. The analyst session API belongs here because the endpoint agent runs on a
// corporate-managed workstation on the corporate network; if analysts ever need Mina from outside
// that network, publishing these is a separate exposure decision and not something to inherit by
// accident.
app.MapMinaSessionEndpoints(MinaListener.Management);
app.MapMinaSensitiveSessionEndpoints(MinaListener.Management);
app.MapMinaAuditEndpoints(MinaListener.Management);
app.MapMinaTamperEndpoints(MinaListener.Management);
app.MapMinaBrowsingDataEndpoints(MinaListener.Management);

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
