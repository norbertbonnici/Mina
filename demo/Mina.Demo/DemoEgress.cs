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
}

/// <summary>
/// The real Envoy running the committed egress configuration. Hostname telemetry comes from
/// Envoy's own access log — the same `mina.hostname.v1` records the production node emits, with no
/// TLS interception anywhere.
/// </summary>
internal sealed class EnvoyDemoEgress : IDemoEgress
{
    private readonly EnvoyProcess _envoy;

    private EnvoyDemoEgress(EnvoyProcess envoy, string serverName)
    {
        _envoy = envoy;
        ServerName = serverName;
    }

    public string Host => "127.0.0.1";

    public int Port => _envoy.IngressPort;

    public string ServerName { get; }

    public string Description => "real Envoy (egress-node/envoy/envoy-bootstrap.yaml)";

    public static async Task<EnvoyDemoEgress> StartAsync(
        string binary, CertificateAuthority authority, string serverName, Action<string> onHostname)
    {
        var envoy = await EnvoyProcess.StartAsync(binary, authority, serverName,
            onOutput: line => ReportHostname(line, onHostname)).ConfigureAwait(false);

        return new EnvoyDemoEgress(envoy, serverName);
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

    public ValueTask DisposeAsync() => _envoy.DisposeAsync();
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
