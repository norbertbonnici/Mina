using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Mina.ControlPlane.Pki;
using Mina.EndpointAgent.Proxy;
using Mina.TestSupport;
using Xunit;

namespace Mina.Transport.Tests;

/// <summary>
/// True interop proof: the real .NET agent (loopback proxy + mTLS tunnel client) talking to a
/// real Envoy process running the committed egress config. Skipped unless MINA_ENVOY points at
/// an Envoy binary, so CI without Envoy stays green; run locally with:
///   MINA_ENVOY=/path/to/envoy dotnet test tests/integration/Mina.Transport.Tests
/// </summary>
public sealed class EnvoyInteropTests
{
    private const string ServerName = "egress.local";
    private static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;

    [SkippableFact]
    public async Task Agent_tunnels_through_real_envoy_and_hostname_is_logged()
    {
        var envoyPath = EnvoyProcess.LocateBinary();
        Skip.If(envoyPath is null, "Set MINA_ENVOY to an Envoy binary to run the interop test.");

        using var ca = CertificateAuthority.Create("Mina Interop CA", Now.AddMinutes(-5), TimeSpan.FromDays(1));
        using var caPublic = ca.PublicCertificate;

        await using var envoy = await EnvoyProcess.StartAsync(envoyPath!, ca, ServerName);
        await using var target = new TcpEchoServer();

        using var sessionCert = ca.IssueClientCertificate(
            "mina-session-interop", "mina:session:interop", Now.AddMinutes(-5), TimeSpan.FromMinutes(60));
        var clientPfx = sessionCert.Export(X509ContentType.Pkcs12);

        var factory = new MtlsTunnelConnectionFactory(
            new EgressEndpoint("127.0.0.1", envoy.IngressPort, ServerName),
            () => X509CertificateLoader.LoadPkcs12(clientPfx, password: null),
            caPublic);

        await using var proxy = new LoopbackConnectProxy(
            factory, new LoopbackPeerAuthorizer(), NullLogger<LoopbackConnectProxy>.Instance);
        proxy.Start();

        var echoed = await BrowserRoundTripAsync(
            proxy.Endpoint!, new ConnectTarget("127.0.0.1", target.Port), "hello-through-envoy");
        Assert.Equal("hello-through-envoy", echoed);

        // Hostname telemetry (ADR-0002 Option 1) is emitted by Envoy without TLS interception.
        var authority = $"127.0.0.1:{target.Port}";
        var logged = await WaitForLogLineAsync(envoy.AccessLogPath, authority);
        Assert.Contains("mina.hostname.v1", logged, StringComparison.Ordinal);
        Assert.Contains(authority, logged, StringComparison.Ordinal);
    }

    private static async Task<string> WaitForLogLineAsync(string path, string mustContain)
    {
        for (var attempt = 0; attempt < 50; attempt++)
        {
            if (File.Exists(path))
            {
                var text = await ReadAllTextSharedAsync(path);
                if (text.Contains(mustContain, StringComparison.Ordinal))
                {
                    return text;
                }
            }

            await Task.Delay(100);
        }

        return File.Exists(path) ? await ReadAllTextSharedAsync(path) : string.Empty;
    }

    private static async Task<string> ReadAllTextSharedAsync(string path)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var reader = new StreamReader(stream);
        return await reader.ReadToEndAsync();
    }

    private static async Task<string> BrowserRoundTripAsync(IPEndPoint proxy, ConnectTarget target, string payload)
    {
        using var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
        await socket.ConnectAsync(proxy);
        await using var stream = new NetworkStream(socket, ownsSocket: false);

        await stream.WriteAsync(HttpConnect.BuildConnectRequest(target));
        Assert.Equal(200, await HttpConnect.ReadResponseStatusAsync(stream, CancellationToken.None));

        var bytes = Encoding.UTF8.GetBytes(payload);
        await stream.WriteAsync(bytes);

        var received = new byte[bytes.Length];
        var offset = 0;
        while (offset < received.Length)
        {
            var read = await stream.ReadAsync(received.AsMemory(offset));
            if (read == 0)
            {
                break;
            }

            offset += read;
        }

        return Encoding.UTF8.GetString(received, 0, offset);
    }
}
