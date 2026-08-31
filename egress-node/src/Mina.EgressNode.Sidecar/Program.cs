// Mina egress-node sidecar (M3-4).
//
// Runs beside Envoy on an egress node and does two things: keeps the node's suppression view
// current from the control plane, and ships Envoy's hostname telemetry upstream — withholding
// destinations for suppressed sessions on the way out.
//
// It is the first line of suppression enforcement, not the guarantee: the control plane re-checks
// every item it receives, so a stale view or a compromised node cannot get a suppressed session's
// destinations recorded (threat N5).

using Mina.EgressNode.Sidecar;

var builder = Host.CreateApplicationBuilder(args);

builder.Services.Configure<SidecarOptions>(builder.Configuration.GetSection(SidecarOptions.Section));

var options = builder.Configuration.GetSection(SidecarOptions.Section).Get<SidecarOptions>() ?? new SidecarOptions();
if (string.IsNullOrWhiteSpace(options.Region))
{
    throw new InvalidOperationException($"{SidecarOptions.Section}:Region is required.");
}

builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<SuppressionAllowlist>();
builder.Services.AddSingleton<TelemetryBatcher>();

// In Azure the node authenticates with its own managed identity. Until the dev subscription exists
// that token comes from configuration, and the sidecar says so rather than pretending otherwise.
builder.Services.AddSingleton<INodeTokenProvider>(sp =>
{
    var token = builder.Configuration["Mina:Sidecar:AccessToken"];
    if (string.IsNullOrWhiteSpace(token))
    {
        throw new InvalidOperationException(
            "No node token configured. Set Mina:Sidecar:AccessToken for development; managed-identity " +
            "token acquisition lands with the Azure deployment (M2-2c/M3-4 follow-up).");
    }

    SidecarStartupLog.UsingConfiguredToken(sp.GetRequiredService<ILogger<Program>>());
    return new ConfiguredNodeTokenProvider(token);
});

builder.Services.AddHttpClient<ControlPlaneNodeClient>(client =>
{
    client.BaseAddress = options.ControlPlaneBaseAddress
        ?? throw new InvalidOperationException($"{SidecarOptions.Section}:ControlPlaneBaseAddress is required.");
});

builder.Services.AddHostedService<AllowlistRefreshService>();
builder.Services.AddHostedService<AccessLogShipperService>();

var host = builder.Build();
host.Run();

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
