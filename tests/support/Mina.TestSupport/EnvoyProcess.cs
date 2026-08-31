using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using Mina.ControlPlane.Pki;

namespace Mina.TestSupport;

/// <summary>
/// Runs a real Envoy against the committed egress configuration
/// (<c>egress-node/envoy/envoy-bootstrap.yaml</c>), with throwaway TLS material issued by the
/// supplied CA. Used by the interop test and by the demo harness, so both exercise the actual
/// egress component rather than a stand-in.
/// </summary>
public sealed class EnvoyProcess : IAsyncDisposable
{
    private readonly Process _process;
    private readonly DirectoryInfo _workingDirectory;
    private readonly StreamWriter _outputWriter;

    private EnvoyProcess(Process process, DirectoryInfo workingDirectory, StreamWriter outputWriter, int ingressPort)
    {
        _process = process;
        _workingDirectory = workingDirectory;
        _outputWriter = outputWriter;
        IngressPort = ingressPort;
    }

    public int IngressPort { get; }

    /// <summary>File Envoy's stdout is captured to — the access log carrying hostname telemetry.</summary>
    public string OutputPath => Path.Combine(_workingDirectory.FullName, "envoy.out");

    /// <summary>The Envoy binary from the MINA_ENVOY environment variable, if it is set and exists.</summary>
    public static string? LocateBinary()
    {
        var path = Environment.GetEnvironmentVariable("MINA_ENVOY");
        return !string.IsNullOrWhiteSpace(path) && File.Exists(path) ? path : null;
    }

    /// <summary>The committed Envoy config in the source tree.</summary>
    public static string LocateConfig() =>
        RepoRoot.Path("egress-node", "envoy", "envoy-bootstrap.yaml");

    /// <summary>
    /// Starts Envoy and waits until its admin endpoint reports ready. <paramref name="onOutput"/>
    /// receives each stdout line as it arrives (the access log).
    /// </summary>
    public static async Task<EnvoyProcess> StartAsync(
        string envoyBinary,
        CertificateAuthority authority,
        string serverName,
        Action<string>? onOutput = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authority);

        var work = Directory.CreateTempSubdirectory("mina-envoy");
        var now = DateTimeOffset.UtcNow;

        using (var caPublic = authority.PublicCertificate)
        {
            File.WriteAllText(Path.Combine(work.FullName, "ca.crt"), caPublic.ExportCertificatePem());
        }

        using (var serverCertificate = authority.IssueServerCertificate(
            serverName, [serverName], [IPAddress.Loopback], now.AddMinutes(-5), TimeSpan.FromHours(4)))
        {
            File.WriteAllText(
                Path.Combine(work.FullName, "server.crt"), serverCertificate.ExportCertificatePem());
            using var key = serverCertificate.GetECDsaPrivateKey()!;
            File.WriteAllText(
                Path.Combine(work.FullName, "server.key"), key.ExportPkcs8PrivateKeyPem());
        }

        var ingressPort = FreePort();
        var adminPort = FreePort();
        var configPath = Path.Combine(work.FullName, "envoy.yaml");
        File.WriteAllText(configPath, File.ReadAllText(LocateConfig())
            .Replace("/etc/mina/tls", work.FullName, StringComparison.Ordinal)
            .Replace("port_value: 8443", $"port_value: {ingressPort}", StringComparison.Ordinal)
            .Replace("port_value: 9901", $"port_value: {adminPort}", StringComparison.Ordinal));

        var startInfo = new ProcessStartInfo(envoyBinary)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        startInfo.ArgumentList.Add("-c");
        startInfo.ArgumentList.Add(configPath);
        startInfo.ArgumentList.Add("--log-level");
        startInfo.ArgumentList.Add("warning");

        var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException($"Could not start Envoy from '{envoyBinary}'.");

        var writer = new StreamWriter(Path.Combine(work.FullName, "envoy.out")) { AutoFlush = true };
        process.OutputDataReceived += (_, e) =>
        {
            if (e.Data is null)
            {
                return;
            }

            writer.WriteLine(e.Data);
            onOutput?.Invoke(e.Data);
        };
        process.ErrorDataReceived += (_, _) => { };
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        var envoy = new EnvoyProcess(process, work, writer, ingressPort);
        try
        {
            await WaitForReadyAsync(adminPort, process, cancellationToken).ConfigureAwait(false);
            return envoy;
        }
        catch
        {
            await envoy.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private static async Task WaitForReadyAsync(int adminPort, Process process, CancellationToken cancellationToken)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromMilliseconds(500) };
        var readyUri = new Uri(
            string.Create(CultureInfo.InvariantCulture, $"http://127.0.0.1:{adminPort}/ready"));

        for (var attempt = 0; attempt < 120; attempt++)
        {
            if (process.HasExited)
            {
                throw new InvalidOperationException($"Envoy exited during startup with code {process.ExitCode}.");
            }

            try
            {
                using var response = await http.GetAsync(readyUri, cancellationToken).ConfigureAwait(false);
                if (response.IsSuccessStatusCode)
                {
                    return;
                }
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
            {
                // not listening yet
            }

            await Task.Delay(150, cancellationToken).ConfigureAwait(false);
        }

        throw new TimeoutException("Envoy did not become ready within the timeout.");
    }

    private static int FreePort()
    {
        using var probe = new Socket(SocketType.Stream, ProtocolType.Tcp);
        probe.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return ((IPEndPoint)probe.LocalEndPoint!).Port;
    }

    public ValueTask DisposeAsync()
    {
        try
        {
            if (!_process.HasExited)
            {
                _process.Kill(entireProcessTree: true);
                _process.WaitForExit(5000);
            }
        }
        catch (InvalidOperationException)
        {
            // already gone
        }

        _process.Dispose();
        _outputWriter.Dispose();

        try
        {
            _workingDirectory.Delete(recursive: true);
        }
        catch (IOException)
        {
            // best effort; the throwaway keys go with the temp directory
        }

        return ValueTask.CompletedTask;
    }
}
