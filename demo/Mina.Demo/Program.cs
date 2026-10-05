// Mina demo harness — DEVELOPMENT ONLY.
//
// Runs the whole platform in one process so the protected path can be driven from a real browser:
//   browser → agent loopback proxy → mTLS tunnel → egress → the internet
// with the real control-plane API issuing the session certificate that authenticates the tunnel.
//
// The one substitution is sign-in: this process hosts the API with a demo authentication handler in
// place of Entra. That substitution lives *here*, in the demo — the shipping control-plane API has
// no bypass in it, and none of this code is part of any deployed artefact.

using System.Globalization;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Mina.ControlPlane.Persistence;
using Mina.ControlPlane.Pki;
using Mina.Demo;
using Mina.EndpointAgent.Configuration;
using Mina.EndpointAgent.Proxy;
using Mina.EndpointAgent.Session;
using Mina.TestSupport;
using Microsoft.Extensions.Options;

const string ServerName = "demo.egress.mina";
const string Region = "westeurope";

var proxyPort = ArgValue(args, "--proxy-port") is { } p
    ? int.Parse(p, CultureInfo.InvariantCulture)
    : 18080;
var uiPort = ArgValue(args, "--ui-port") is { } u
    ? int.Parse(u, CultureInfo.InvariantCulture)
    : 18081;
var envoyBinary = ArgValue(args, "--envoy") ?? EnvoyProcess.LocateBinary();

Banner();

using var authority = CertificateAuthority.Create(
    "Mina Demo CA", DateTimeOffset.UtcNow.AddMinutes(-5), TimeSpan.FromDays(1));
using var caPublic = authority.PublicCertificate;

// 1. Egress ------------------------------------------------------------------------------------
IDemoEgress egress = envoyBinary is not null
    ? await EnvoyDemoEgress.StartAsync(envoyBinary, authority, ServerName, ReportHostname)
    : StubDemoEgress.Start(authority, ServerName, ReportHostname);

await using (egress)
{
    Step("Egress", $"{egress.Description} on {egress.Host}:{egress.Port}");

    // 2. Control plane ---------------------------------------------------------------------------
    // Shared stores so the management UI sees exactly the sessions and approvals the API creates.
    var sessionStore = new InMemorySessionRepository();
    var requestStore = new InMemorySensitiveSessionRepository();

    using var controlPlane = new ControlPlaneHost(
        authority, egress.Host, egress.Port, ServerName, leaseTtl: TimeSpan.FromMinutes(15),
        sharedSessions: sessionStore, sharedRequests: requestStore);
    using var httpClient = controlPlane.CreateClient();
    Step("Control plane", "real ASP.NET Core API in-process (demo sign-in stands in for Entra)");

    // 3. Management UI ---------------------------------------------------------------------------
    var managementUi = await ManagementUiHost.StartAsync(
        uiPort, sessionStore, sessionStore, requestStore,
        approvedRegions: ["westeurope", "northeurope", "germanywestcentral", "francecentral"],
        activeRegions: [Region],
        approverUpn: "manager@example.org");
    Step("Management UI", $"http://127.0.0.1:{uiPort}  (signed in as manager@example.org, approver)");

    // 4. Agent -----------------------------------------------------------------------------------
    var token = BearerTestAuthHandler.Token(
        "oid-demo-analyst", "analyst@example.org", "device-demo-1", "Mina.Analyst");

    var options = Options.Create(new MinaAgentOptions
    {
        Region = Region,
        EgressCaCertificatePem = caPublic.ExportCertificatePem(),
        // Wide margin so "n" always rotates the credential on demand.
        RenewMargin = TimeSpan.FromHours(24),
    });

    await using var sessions = new ResearchSessionManager(
        new ControlPlaneClient(httpClient, new ConfiguredAccessTokenProvider(token)),
        options,
        TimeProvider.System,
        Microsoft.Extensions.Logging.Abstractions.NullLogger<ResearchSessionManager>.Instance);

    // The agent's client attaches this per request; the demo's direct API calls need it as well.
    httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

    var tunnelFactory = new SessionTunnelConnectionFactory(sessions);
    LoopbackConnectProxy? proxy = null;
    Guid? pendingRequestId = null;

    try
    {
        await EstablishAsync();
        await OpenProxyAsync();
        Instructions(proxyPort);
        await KeyLoopAsync();
    }
    finally
    {
        if (proxy is not null)
        {
            await proxy.DisposeAsync();
        }

        await managementUi.StopAsync();
        await managementUi.DisposeAsync();
    }

    async Task EstablishAsync()
    {
        try
        {
            var session = await sessions.EstablishAsync(CancellationToken.None);
            // Since M4-11 a certificate is not enough at the real Envoy — the sidecar's session
            // view has to list it too. The demo has no independent allowlist-pull loop, so it
            // tells the egress directly, standing in for what a poll would have picked up.
            egress.SetLiveSession(session.SessionId);
            Step("Session", $"{session.SessionId} · region {session.Region} · mode {session.Mode} · " +
                            $"lease to {session.LeaseExpiresAt.ToLocalTime():HH:mm:ss} · " +
                            $"cert {session.CertificateSerialNumber[..8]}…");
        }
        catch (ControlPlaneException ex)
        {
            Warn($"The control plane refused the session: {ex.Message}");
        }
    }

    async Task OpenProxyAsync()
    {
        proxy = new LoopbackConnectProxy(
            tunnelFactory, new LoopbackPeerAuthorizer(),
            Microsoft.Extensions.Logging.Abstractions.NullLogger<LoopbackConnectProxy>.Instance);
        proxy.Start(proxyPort);
        Step("Protected path", $"OPEN — proxy listening on 127.0.0.1:{proxy.Endpoint!.Port}");
    }

    async Task CloseProxyAsync()
    {
        if (proxy is not null)
        {
            await proxy.DisposeAsync();
            proxy = null;
        }
    }

    // Reads a command from the console, or from piped input when stdin is not a terminal (which is
    // also how the harness is exercised non-interactively). At end of input it simply stays up.
    static async Task<char> NextCommandAsync()
    {
        if (!Console.IsInputRedirected)
        {
            return Console.ReadKey(intercept: true).KeyChar;
        }

        var line = await Console.In.ReadLineAsync();
        if (line is null)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan);
        }

        return string.IsNullOrEmpty(line) ? ' ' : line[0];
    }

    // The analyst asks for URL-telemetry suppression on the live session. The approver then decides
    // in the management UI — nothing here can approve it.
    async Task RequestSuppressionAsync()
    {
        var session = sessions.Current;
        if (session is null)
        {
            Warn("No live session to request suppression for; press r first.");
            return;
        }

        using var response = await httpClient.PostAsJsonAsync(
            $"api/sessions/{session.SessionId}/sensitive",
            new { justificationReference = "CASE-2026-0042", requestedMinutes = 60 });

        if (!response.IsSuccessStatusCode)
        {
            Warn($"The control plane refused the request ({(int)response.StatusCode}).");
            return;
        }

        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        pendingRequestId = document.RootElement.GetProperty("requestId").GetGuid();
        Step("Suppression", $"requested (ref CASE-2026-0042, 60 min) — request {pendingRequestId}");
        Info($"Now approve it as the manager at http://127.0.0.1:{uiPort}/approvals, then press v.");
    }

    // Activates an approval somebody else granted. Without that approval this call is refused.
    async Task ActivateSuppressionAsync()
    {
        if (pendingRequestId is null)
        {
            Warn("No request to activate; press a first.");
            return;
        }

        using var response = await httpClient.PostAsync(
            $"api/sensitive-requests/{pendingRequestId}/activate", content: null);

        if (!response.IsSuccessStatusCode)
        {
            Warn($"Activation refused ({(int)response.StatusCode}). " +
                 "Suppression needs an approval recorded by someone other than the analyst.");
            return;
        }

        Step("Suppression", "ACTIVE — the egress stops recording hostnames for this session.");
        Info("The session now shows as Sensitive in the management UI's Sessions screen.");
    }

    async Task KeyLoopAsync()
    {
        while (true)
        {
            var key = await NextCommandAsync();
            Console.WriteLine();
            switch (char.ToLowerInvariant(key))
            {
                case 'k':
                    await sessions.EndAsync(CancellationToken.None);
                    egress.SetLiveSession(null);
                    await CloseProxyAsync();
                    Warn("Session ended and the proxy torn down. The browser now has NO route out — " +
                         "reload a page and it will fail. Nothing falls back to ordinary egress.");
                    break;

                case 'r':
                    await EstablishAsync();
                    if (sessions.Current is not null)
                    {
                        await OpenProxyAsync();
                        Info("Browsing works again on the same port.");
                    }

                    break;

                case 'n':
                    if (await sessions.RenewIfDueAsync(CancellationToken.None))
                    {
                        var s = sessions.Current!;
                        egress.SetLiveSession(s.SessionId); // same id, but refreshes the lease the sidecar sees
                        Step("Renewed", $"same session {s.SessionId} · NEW cert {s.CertificateSerialNumber[..8]}… · " +
                                        $"lease to {s.LeaseExpiresAt.ToLocalTime():HH:mm:ss}");
                    }
                    else
                    {
                        Warn("Nothing to renew — there is no live session.");
                    }

                    break;

                case 'a':
                    await RequestSuppressionAsync();
                    break;

                case 'v':
                    await ActivateSuppressionAsync();
                    break;

                case 's':
                    var current = sessions.Current;
                    if (current is null)
                    {
                        Warn("No session. Protected path CLOSED.");
                    }
                    else
                    {
                        Info($"Session {current.SessionId} · region {current.Region} · mode {current.Mode} · " +
                             $"lease to {current.LeaseExpiresAt.ToLocalTime():HH:mm:ss} · path " +
                             (proxy is null ? "CLOSED" : $"OPEN on 127.0.0.1:{proxy.Endpoint!.Port}"));
                    }

                    break;

                case 'q':
                    Info("Shutting down; the session is ended with the control plane.");
                    return;

                default:
                    Menu();
                    break;
            }
        }
    }
}

static string? ArgValue(string[] args, string name)
{
    var index = Array.IndexOf(args, name);
    return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
}

static void Banner()
{
    Console.WriteLine();
    WriteColour(ConsoleColor.Cyan, "  Mina — secure research egress demo");
    Console.WriteLine("  Development harness. Not a deployable artefact.");
    Console.WriteLine();
}

static void Step(string label, string detail)
{
    WriteColour(ConsoleColor.Green, $"  ✓ {label,-16}", newLine: false);
    Console.WriteLine(detail);
}

static void Info(string message)
{
    WriteColour(ConsoleColor.Cyan, "  · ", newLine: false);
    Console.WriteLine(message);
}

static void Warn(string message)
{
    WriteColour(ConsoleColor.Yellow, "  ! ", newLine: false);
    Console.WriteLine(message);
}

static void ReportHostname(string authority)
{
    WriteColour(ConsoleColor.DarkGray, $"  → egress saw  {authority}");
}

static void Instructions(int port)
{
    Console.WriteLine();
    WriteColour(ConsoleColor.Cyan, "  Point a browser (or curl) at the protected path:");
    Console.WriteLine();
    Console.WriteLine($"    curl -x http://127.0.0.1:{port} https://example.com -sSo /dev/null -w '%{{http_code}}\\n'");
    Console.WriteLine();
    Console.WriteLine($"    Firefox: Settings → Network Settings → Manual proxy, HTTP proxy 127.0.0.1 : {port},");
    Console.WriteLine("             tick \"Also use this proxy for HTTPS\".");
    Console.WriteLine($"    Chrome/Edge:  --proxy-server=\"http://127.0.0.1:{port}\" on the command line");
    Console.WriteLine("                  (this is what the agent will pass the research browser).");
    Console.WriteLine();
    Console.WriteLine("  Every site you visit is listed below as the egress sees it: hostname only,");
    Console.WriteLine("  never the URL path — no TLS interception (ADR-0002).");
    Console.WriteLine();
    Menu();
}

static void Menu()
{
    WriteColour(ConsoleColor.Cyan,
        "  [k] kill session (fail closed)   [r] re-establish   [n] renew cert   [s] status   [q] quit");
    WriteColour(ConsoleColor.Cyan,
        "  [a] request suppression (analyst)                   [v] activate once approved");
    Console.WriteLine();
}

static void WriteColour(ConsoleColor colour, string text, bool newLine = true)
{
    var previous = Console.ForegroundColor;
    Console.ForegroundColor = colour;
    if (newLine)
    {
        Console.WriteLine(text);
    }
    else
    {
        Console.Write(text);
    }

    Console.ForegroundColor = previous;
}
