// Mina endpoint agent.
//
// Wires the protected path: acquire an Entra token, ask the control plane for a session (sending a
// CSR whose private key never leaves this device), and serve the research browser through a
// loopback CONNECT proxy that forwards only over the authenticated mTLS tunnel. No session means no
// listener, so the browser fails closed rather than falling back to ordinary corporate egress.
//
// Still to come (M2-4, Windows-specific): MSAL/WAM silent sign-in in place of the configured-token
// provider, WFP enforcement, the peer check that verifies the connecting process is the managed
// research browser, and launching that browser. The tray UI is served from here over a named pipe.

using Mina.EndpointAgent;
using Mina.EndpointAgent.Configuration;
using Mina.EndpointAgent.Ipc;
using Mina.EndpointAgent.Proxy;
using Mina.EndpointAgent.Session;
using Mina.Observability;

var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddWindowsService(options => options.ServiceName = "MinaEndpointAgent");
builder.Services.Configure<MinaAgentOptions>(builder.Configuration.GetSection(MinaAgentOptions.Section));

var agentOptions = builder.Configuration.GetSection(MinaAgentOptions.Section).Get<MinaAgentOptions>()
    ?? new MinaAgentOptions();

// The agent proxies research traffic, so its own logs name destinations. Telemetry leaves here
// only through the scrubbing pipeline.
builder.Services.AddMinaObservability(builder.Configuration, aspNetCore: false);

builder.Services.AddSingleton(TimeProvider.System);

// Development token provider. The production provider (MSAL.NET + WAM broker) is Windows-only and
// arrives with M2-4; until then a token must be supplied in configuration, and the agent says so.
builder.Services.AddSingleton<IAccessTokenProvider>(sp =>
{
    var token = builder.Configuration["Mina:Agent:AccessToken"];
    if (string.IsNullOrWhiteSpace(token))
    {
        throw new InvalidOperationException(
            "No access token configured. Set Mina:Agent:AccessToken for development; interactive " +
            "Entra sign-in via the WAM broker lands with M2-4.");
    }

    AgentStartupLog.UsingConfiguredAccessToken(sp.GetRequiredService<ILogger<ProtectedPathWorker>>());
    return new ConfiguredAccessTokenProvider(token);
});

builder.Services.AddHttpClient<ControlPlaneClient>(client =>
{
    client.BaseAddress = agentOptions.ControlPlaneBaseAddress
        ?? throw new InvalidOperationException("Mina:Agent:ControlPlaneBaseAddress is required.");
});

builder.Services.AddSingleton<ResearchSessionManager>();
builder.Services.AddSingleton<SessionTunnelConnectionFactory>();

// Shared between the worker that maintains the protected path and the tray that reports it.
builder.Services.AddSingleton<AgentRuntimeState>();
builder.Services.AddSingleton<TrayControlService>();
builder.Services.AddSingleton<ITrayControl>(sp => sp.GetRequiredService<TrayControlService>());
builder.Services.AddSingleton<ISessionControl>(sp => sp.GetRequiredService<ResearchSessionManager>());

// PoC peer check: loopback only. Verifying the connecting process is the managed research browser
// is Windows-specific and lands with M2-4 (THREAT_MODEL B1).
builder.Services.AddSingleton<IPeerAuthorizer, LoopbackPeerAuthorizer>();

builder.Services.AddHostedService<ProtectedPathWorker>();

// The per-user tray connects here. It is a privilege boundary — the agent runs as SYSTEM and the
// tray as the interactive user — so the pipe is ACL'd and every request is re-validated server-side.
builder.Services.AddHostedService<TrayIpcServer>();

var host = builder.Build();
host.Run();
