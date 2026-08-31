using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
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
    private static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;

    [SkippableFact]
    public async Task Agent_tunnels_through_real_envoy_and_hostname_is_logged()
    {
        var envoyPath = Environment.GetEnvironmentVariable("MINA_ENVOY");
        Skip.If(string.IsNullOrWhiteSpace(envoyPath) || !File.Exists(envoyPath),
            "Set MINA_ENVOY to an Envoy binary to run the interop test.");

        var work = Directory.CreateTempSubdirectory("mina-envoy-interop");
        Process? envoy = null;
        try
        {
            using var ca = CertificateAuthority.Create("Mina Interop CA", Now.AddMinutes(-5), TimeSpan.FromDays(1));
            using var caPublic = ca.PublicCertificate;
            using var serverCert = ca.IssueServerCertificate(
                "egress.local", ["egress.local"], [IPAddress.Loopback], Now.AddMinutes(-5), TimeSpan.FromHours(1));

            WritePem(Path.Combine(work.FullName, "ca.crt"), caPublic.ExportCertificatePem());
            WritePem(Path.Combine(work.FullName, "server.crt"), serverCert.ExportCertificatePem());
            using (var key = serverCert.GetECDsaPrivateKey()!)
            {
                WritePem(Path.Combine(work.FullName, "server.key"), key.ExportPkcs8PrivateKeyPem());
            }

            var ingressPort = FreePort();
            var adminPort = FreePort();
            var configPath = WriteConfig(work.FullName, ingressPort, adminPort);

            envoy = StartEnvoy(envoyPath!, configPath, work.FullName);
            await WaitForReadyAsync(adminPort, envoy);

            await using var target = new TcpEchoServer();

            using var sessionCert = ca.IssueClientCertificate(
                "mina-session-interop", "mina:session:interop", Now.AddMinutes(-5), TimeSpan.FromMinutes(60));
            var clientPfx = sessionCert.Export(X509ContentType.Pkcs12);
            var factory = new MtlsTunnelConnectionFactory(
                new EgressEndpoint("127.0.0.1", ingressPort, "egress.local"),
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
            var logged = await WaitForLogLineAsync(Path.Combine(work.FullName, "envoy.out"), authority);
            Assert.Contains("mina.hostname.v1", logged, StringComparison.Ordinal);
            Assert.Contains(authority, logged, StringComparison.Ordinal);
        }
        finally
        {
            if (envoy is { HasExited: false })
            {
                envoy.Kill(entireProcessTree: true);
            }

            envoy?.Dispose();
            try
            {
                work.Delete(recursive: true);
            }
            catch (IOException)
            {
                // best effort
            }
        }
    }

    private static string WriteConfig(string dir, int ingressPort, int adminPort)
    {
        var repoConfig = LocateRepoConfig();
        var yaml = File.ReadAllText(repoConfig)
            .Replace("/etc/mina/tls", dir, StringComparison.Ordinal)
            .Replace("port_value: 8443", $"port_value: {ingressPort}", StringComparison.Ordinal)
            .Replace("port_value: 9901", $"port_value: {adminPort}", StringComparison.Ordinal);
        var path = Path.Combine(dir, "envoy.yaml");
        File.WriteAllText(path, yaml);
        return path;
    }

    private static string LocateRepoConfig()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, "egress-node", "envoy", "envoy-bootstrap.yaml");
            if (File.Exists(candidate))
            {
                return candidate;
            }

            dir = dir.Parent;
        }

        throw new FileNotFoundException("Could not locate egress-node/envoy/envoy-bootstrap.yaml from the test output directory.");
    }

    private static Process StartEnvoy(string envoyPath, string configPath, string workDir)
    {
        var stdout = Path.Combine(workDir, "envoy.out");
        var psi = new ProcessStartInfo(envoyPath)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        psi.ArgumentList.Add("-c");
        psi.ArgumentList.Add(configPath);
        psi.ArgumentList.Add("--log-level");
        psi.ArgumentList.Add("warning");

        var process = Process.Start(psi)!;
        // Envoy access logs go to stdout (our hostname telemetry) — capture to a file.
        var writer = new StreamWriter(stdout) { AutoFlush = true };
        process.OutputDataReceived += (_, e) => { if (e.Data is not null) { writer.WriteLine(e.Data); } };
        process.ErrorDataReceived += (_, _) => { };
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        return process;
    }

    private static async Task WaitForReadyAsync(int adminPort, Process envoy)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromMilliseconds(500) };
        for (var attempt = 0; attempt < 100; attempt++)
        {
            Skip.If(envoy.HasExited, $"Envoy exited early with code {(envoy.HasExited ? envoy.ExitCode : 0)}.");
            try
            {
                var response = await http.GetAsync(new Uri($"http://127.0.0.1:{adminPort}/ready"));
                if (response.IsSuccessStatusCode)
                {
                    return;
                }
            }
            catch (HttpRequestException)
            {
                // not up yet
            }
            catch (TaskCanceledException)
            {
                // timeout, retry
            }

            await Task.Delay(150);
        }

        throw new TimeoutException("Envoy did not become ready within the timeout.");
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

    private static void WritePem(string path, string pem) => File.WriteAllText(path, pem);

    private static int FreePort()
    {
        using var probe = new Socket(SocketType.Stream, ProtocolType.Tcp);
        probe.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return ((IPEndPoint)probe.LocalEndPoint!).Port;
    }

    private static async Task<string> BrowserRoundTripAsync(IPEndPoint proxy, ConnectTarget target, string payload)
    {
        using var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
        await socket.ConnectAsync(proxy);
        await using var stream = new NetworkStream(socket, ownsSocket: false);

        await stream.WriteAsync(HttpConnect.BuildConnectRequest(target));
        var status = await HttpConnect.ReadResponseStatusAsync(stream, CancellationToken.None);
        Assert.Equal(200, status);

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
