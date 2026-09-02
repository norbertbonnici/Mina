// Mina egress-node sidecar (M3-4, M4-11).
//
// Runs beside Envoy on an egress node and does three things: keeps the node's session view current
// from the control plane; answers Envoy's admission check for every tunnel, so a revoked session is
// refused within a refresh interval rather than a certificate lifetime; and ships Envoy's hostname
// telemetry upstream — withholding destinations for suppressed sessions on the way out.
//
// Admission fails closed: Envoy is configured to refuse the tunnel when this process does not
// answer, so the sidecar being down stops browsing on the node rather than opening it. Suppression
// here is the first line of that enforcement, not the guarantee: the control plane re-checks every
// item it receives, so a stale view or a compromised node cannot get a suppressed session's
// destinations recorded (threat N5).

using Microsoft.AspNetCore.Builder;
using Mina.EgressNode.Sidecar;
using Mina.Observability;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOptions<SidecarOptions>()
    .Bind(builder.Configuration.GetSection(SidecarOptions.Section))
    .Validate(o => !o.Validate().Any(), "Invalid Mina:Sidecar configuration.")
    .ValidateOnStart();

var options = builder.Configuration.GetSection(SidecarOptions.Section).Get<SidecarOptions>() ?? new SidecarOptions();
var problems = options.Validate().ToList();
if (problems.Count > 0)
{
    throw new InvalidOperationException(string.Join(" ", problems));
}

// The sidecar handles hostnames by definition; scrubbing applies to its telemetry too. The
// ASP.NET Core instrumentation stays off: the only HTTP server here is the admission socket, and a
// span per CONNECT would be volume without information.
builder.Services.AddMinaObservability(builder.Configuration, aspNetCore: false);

builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<NodeSessionView>();
builder.Services.AddSingleton<TelemetryBatcher>();

// In Azure the node authenticates with its own managed identity. Until the dev subscription exists
// that token comes from configuration, and the sidecar says so rather than pretending otherwise.
builder.Services.AddSingleton<INodeTokenProvider>(sp =>
{
    // Configuration, or a systemd credential (LoadCredential=mina-node-token:…) — a file only this
    // unit's user can read, which is where a bearer token belongs on a shared host.
    var token = builder.Configuration["Mina:Sidecar:AccessToken"];
    if (string.IsNullOrWhiteSpace(token)
        && Environment.GetEnvironmentVariable("CREDENTIALS_DIRECTORY") is { Length: > 0 } credentials
        && File.Exists(Path.Combine(credentials, "mina-node-token")))
    {
        token = File.ReadAllText(Path.Combine(credentials, "mina-node-token")).Trim();
    }

    if (string.IsNullOrWhiteSpace(token))
    {
        throw new InvalidOperationException(
            "No node token configured. Set Mina:Sidecar:AccessToken or provide the mina-node-token credential " +
            "for development; managed-identity token acquisition lands with the Azure deployment (M2-2c/M3-4 follow-up).");
    }

    SidecarStartupLog.UsingConfiguredToken(sp.GetRequiredService<ILogger<Program>>());
    return new ConfiguredNodeTokenProvider(token!);
});

builder.Services.AddHttpClient<ControlPlaneNodeClient>(client =>
{
    client.BaseAddress = options.ControlPlaneBaseAddress;
});

// One refresher, reachable both as the timer-driven service and as the on-demand refresh the
// admission check uses for a session it has not heard of yet.
builder.Services.AddSingleton<AllowlistRefreshService>();
builder.Services.AddSingleton<ISessionViewRefresher>(sp => sp.GetRequiredService<AllowlistRefreshService>());
builder.Services.AddHostedService(sp => sp.GetRequiredService<AllowlistRefreshService>());
builder.Services.AddHostedService<AccessLogShipperService>();

// Type=notify: READY=1 goes to systemd when the host has started, i.e. after the admission socket
// is bound, so mina-envoy.service's After= means the socket exists.
builder.Host.UseSystemd();

// The admission socket. This is the only listener the process has.
builder.AddSessionAdmissionListener(options.AuthzSocketPath);

var app = builder.Build();
app.UseSessionAdmission();
app.Run();

/// <summary>Startup diagnostics for the sidecar.</summary>
internal static partial class SidecarStartupLog
{
    [LoggerMessage(Level = LogLevel.Warning,
        Message = "Using a configured node token. This is a development stand-in for the node's managed " +
                  "identity and cannot observe revocation.")]
    public static partial void UsingConfiguredToken(ILogger logger);
}

/// <summary>Development token provider; production uses the node's managed identity.</summary>
internal sealed class ConfiguredNodeTokenProvider(string token) : INodeTokenProvider
{
    public Task<string> GetTokenAsync(CancellationToken cancellationToken) => Task.FromResult(token);
}
