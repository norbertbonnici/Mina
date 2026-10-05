// Mina endpoint agent.
//
// Wires the protected path: acquire an Entra token, ask the control plane for a session (sending a
// CSR whose private key never leaves this device), and serve the research browser through a
// loopback CONNECT proxy that forwards only over the authenticated mTLS tunnel. No session means no
// listener, so the browser fails closed rather than falling back to ordinary corporate egress.
//
// Still to come (M2-4, Windows-specific): tamper telemetry. The tray UI is served from here over a
// named pipe; both the WAM sign-in relay and the research-browser launch now live there too, since
// the agent runs as SYSTEM in session 0 and cannot reach the interactive user's WAM/PRT itself or
// spawn a process onto their desktop -- see TrayFedAccessTokenProvider and (in
// Mina.EndpointAgent.Tray) WamTokenAcquirer/ResearchBrowserLauncher. The peer check (verifying the
// connecting process is the managed research browser) and WFP enforcement (blocking that browser's
// traffic outside the protected path) have both shipped -- see WindowsPeerAuthorizer and
// WindowsFirewallEnforcer.

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

// Always registered: it is plain state with no OS dependency, and TrayControlService takes it
// directly so the pipe can accept a token and surface a pending claims challenge regardless of
// which IAccessTokenProvider the control-plane client is actually using.
builder.Services.AddSingleton<TrayFedAccessTokenProvider>();

// Production sign-in is the WAM broker, run by the tray (session 0 means the agent cannot do it
// itself — see TrayFedAccessTokenProvider's remarks) and relayed over the pipe. A configured token
// remains available for development and cross-platform testing, where there is no tray and no WAM.
builder.Services.AddSingleton<IAccessTokenProvider>(sp =>
{
    var token = builder.Configuration["Mina:Agent:AccessToken"];
    if (!string.IsNullOrWhiteSpace(token))
    {
        AgentStartupLog.UsingConfiguredAccessToken(sp.GetRequiredService<ILogger<ProtectedPathWorker>>());
        return new ConfiguredAccessTokenProvider(token);
    }

    if (OperatingSystem.IsWindows())
    {
        return sp.GetRequiredService<TrayFedAccessTokenProvider>();
    }

    throw new InvalidOperationException(
        "No access token configured. Set Mina:Agent:AccessToken for development; on Windows without " +
        "it, the agent waits for the tray to supply one via the WAM broker (M2-4).");
});

builder.Services.AddHttpClient<ControlPlaneClient>(client =>
{
    client.BaseAddress = agentOptions.ControlPlaneBaseAddress
        ?? throw new InvalidOperationException("Mina:Agent:ControlPlaneBaseAddress is required.");
});

builder.Services.AddSingleton<ResearchSessionManager>();
builder.Services.AddSingleton<SessionTunnelConnectionFactory>();

// Tamper self-monitoring (M2-4, ARCHITECTURE §3.1 point 5): reports indicators detected in the
// firewall-rule and loopback-peer checks below to the control plane's audit trail. Registered
// unconditionally -- it is plain HTTP, no OS dependency -- so both the Windows detectors and the
// cross-platform stand-ins that don't detect anything still see a real ITamperReporter rather than
// having to special-case its absence.
builder.Services.AddSingleton<ITamperReporter, TamperReporter>();

// Shared between the worker that maintains the protected path and the tray that reports it.
builder.Services.AddSingleton<AgentRuntimeState>();
builder.Services.AddSingleton<TrayControlService>();
builder.Services.AddSingleton<ITrayControl>(sp => sp.GetRequiredService<TrayControlService>());
builder.Services.AddSingleton<ISessionControl>(sp => sp.GetRequiredService<ResearchSessionManager>());

// Peer check (M2-4, THREAT_MODEL B1): verifies the connecting process is the managed research
// browser, by image path and its dedicated profile directory, resolved from the live TCP
// connection table -- Windows-specific, so this agent's actual production path (it deploys and
// runs only on Windows) gets the real control, and anything else (the cross-platform "dotnet"
// build/test path this project also supports) keeps the loopback-only stand-in rather than fail
// to start entirely over an OS check nothing in that path needs to pass.
if (OperatingSystem.IsWindows())
{
    builder.Services.AddSingleton<IPeerAuthorizer, WindowsPeerAuthorizer>();
    builder.Services.AddSingleton<WindowsFirewallEnforcer>();

    // M2-4's last two tamper indicators: unmanaged_browser_instance and flag_mismatch, plus
    // continuous (not just startup-time) re-checking of the WFP rule the block above only confirms
    // once. See BrowserIntegrityMonitor's own remarks for why this needs a real periodic process
    // scan rather than a report wired into an existing check.
    builder.Services.AddHostedService<BrowserIntegrityMonitor>();
}
else
{
    builder.Services.AddSingleton<IPeerAuthorizer, LoopbackPeerAuthorizer>();
}

builder.Services.AddHostedService<ProtectedPathWorker>();

// The per-user tray connects here. It is a privilege boundary — the agent runs as SYSTEM and the
// tray as the interactive user — so the pipe is ACL'd and every request is re-validated server-side.
builder.Services.AddHostedService<TrayIpcServer>();

var host = builder.Build();

// WFP enforcement (M2-4, ARCHITECTURE §3.1): confirmed here, before the protected path can ever
// open, for the same reason the control plane resolves its CA before serving requests -- an agent
// that started without being able to confirm the block rule is in place would be a protected path
// that isn't actually protected. Fatal on failure by design; there is no degraded mode for this.
if (OperatingSystem.IsWindows())
{
    host.Services.GetRequiredService<WindowsFirewallEnforcer>()
        .EnsureAppliedAsync(CancellationToken.None).GetAwaiter().GetResult();
}

host.Run();
