using System.Net;
using System.Text.Json;
using Mina.ControlPlane.Pki;
using Mina.TestSupport;

namespace Mina.Demo;

/// <summary>Where the demo's research traffic exits, and how it reports what it saw.</summary>
internal interface IDemoEgress : IAsyncDisposable
{
    string Host { get; }

    int Port { get; }

    string ServerName { get; }

    /// <summary>What this egress is, shown to the operator so the demo never overstates itself.</summary>
    string Description { get; }

    /// <summary>
    /// Tells the egress which session is live, if any. On the real Envoy this is what admits or
    /// refuses a tunnel (D-19, M4-11) — a certificate alone is no longer enough. The stub does not
    /// implement session admission at all (it never did; D-14 predates it and the stub is scoped to
    /// mTLS + CONNECT), so a null session there changes nothing observable.
    /// </summary>
    void SetLiveSession(Guid? sessionId);
}

/// <summary>
/// The real Envoy running the committed egress configuration. Hostname telemetry comes from
/// Envoy's own access log — the same `mina.hostname.v1` records the production node emits, with no
/// TLS interception anywhere.
/// </summary>
internal sealed class EnvoyDemoEgress : IDemoEgress
{
    private readonly EnvoyProcess _envoy;
    private readonly SidecarAdmissionHost _admission;

    private readonly CancellationTokenSource _stopping = new();

    private EnvoyDemoEgress(EnvoyProcess envoy, SidecarAdmissionHost admission, string serverName)
    {
        _envoy = envoy;
        _admission = admission;
        ServerName = serverName;
    }

    public string Host => "127.0.0.1";

    public int Port => _envoy.IngressPort;

    public string ServerName { get; }

    public string Description => "real Envoy (egress-node/envoy/envoy-bootstrap.yaml)";

    public void SetLiveSession(Guid? sessionId)
    {
        if (sessionId is { } id)
        {
            _admission.Admit(id);
        }
        else
        {
            _admission.RevokeAll();
        }
    }

    public static async Task<EnvoyDemoEgress> StartAsync(
        string binary, CertificateAuthority authority, string serverName, Action<string> onHostname)
    {
        // Since M4-11 the real Envoy config admits nothing without the sidecar's ext_authz answer,
        // so this demo runs the same admission host the real-Envoy interop tests use — a real
        // Kestrel gRPC service on the Unix socket Envoy is configured to call, not a stand-in for
        // the check itself. Starting with no session admitted, matching a freshly booted node.
        var work = Directory.CreateTempSubdirectory("mina-demo-envoy");
        var admission = await SidecarAdmissionHost.StartAsync(EnvoyProcess.AuthzSocketPathFor(work)).ConfigureAwait(false);
        admission.RevokeAll(); // loads the view (empty) rather than leaving it "never refreshed"

        var envoy = await EnvoyProcess.StartAsync(binary, authority, serverName, workingDirectory: work).ConfigureAwait(false);
        var demo = new EnvoyDemoEgress(envoy, admission, serverName);

        // Envoy writes its access log to a file — the same one the node sidecar consumes — so the
        // demo follows that file rather than the process's stdout.
        _ = demo.TailAccessLogAsync(onHostname);
        return demo;
    }

    private async Task TailAccessLogAsync(Action<string> onHostname)
    {
        while (!_stopping.IsCancellationRequested)
        {
            try
            {
                if (!File.Exists(_envoy.AccessLogPath))
                {
                    await Task.Delay(250, _stopping.Token).ConfigureAwait(false);
                    continue;
                }

                await using var stream = new FileStream(
                    _envoy.AccessLogPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var reader = new StreamReader(stream);

                while (!_stopping.IsCancellationRequested)
                {
                    var line = await reader.ReadLineAsync(_stopping.Token).ConfigureAwait(false);
                    if (line is null)
                    {
                        await Task.Delay(200, _stopping.Token).ConfigureAwait(false);
                        continue;
                    }

                    ReportHostname(line, onHostname);
                }
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (IOException)
            {
                await Task.Delay(250).ConfigureAwait(false);
            }
        }
    }

    /// <summary>Pulls the authority out of an access-log line, ignoring Envoy's other output.</summary>
    private static void ReportHostname(string line, Action<string> onHostname)
    {
        if (!line.StartsWith('{'))
        {
            return;
        }

        try
        {
            using var document = JsonDocument.Parse(line);
            if (document.RootElement.TryGetProperty("authority", out var authority)
                && authority.GetString() is { Length: > 0 } value)
            {
                onHostname(value);
            }
        }
        catch (JsonException)
        {
            // not an access-log record
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _stopping.CancelAsync().ConfigureAwait(false);
        _stopping.Dispose();
        await _envoy.DisposeAsync().ConfigureAwait(false);
        await _admission.DisposeAsync().ConfigureAwait(false);
    }
}

/// <summary>
/// In-process stand-in used when no Envoy binary is available. It enforces the same mTLS + CONNECT
/// contract, but it is **not** the production egress component — the demo says so on screen.
/// </summary>
internal sealed class StubDemoEgress : IDemoEgress
{
    private readonly TestEgress _egress;
    private readonly IDisposable _serverCertificate;
    private readonly IDisposable _caPublicCertificate;

    private StubDemoEgress(
        TestEgress egress, IDisposable serverCertificate, IDisposable caPublicCertificate, string serverName)
    {
        _egress = egress;
        _serverCertificate = serverCertificate;
        _caPublicCertificate = caPublicCertificate;
        ServerName = serverName;
    }

    public string Host => IPAddress.Loopback.ToString();

    public int Port => _egress.Endpoint.Port;

    public string ServerName { get; }

    public string Description => "in-process stand-in (set MINA_ENVOY to run the real Envoy instead)";

    public void SetLiveSession(Guid? sessionId)
    {
        // No-op: the stub never implemented session admission (it predates D-19/M4-11 and is
        // scoped to mTLS + CONNECT only), so there is nothing here for a session to change.
    }

    public static StubDemoEgress Start(CertificateAuthority authority, string serverName, Action<string> onHostname)
    {
        var now = DateTimeOffset.UtcNow;
        var serverCertificate = authority.IssueServerCertificate(
            serverName, [serverName], [IPAddress.Loopback], now.AddMinutes(-5), TimeSpan.FromHours(4));
        var caPublic = authority.PublicCertificate;

        var egress = new TestEgress(serverCertificate, caPublic) { OnAuthorityObserved = onHostname };
        return new StubDemoEgress(egress, serverCertificate, caPublic, serverName);
    }

    public async ValueTask DisposeAsync()
    {
        await _egress.DisposeAsync().ConfigureAwait(false);
        _serverCertificate.Dispose();
        _caPublicCertificate.Dispose();
    }
}
