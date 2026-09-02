using System.Diagnostics;
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

    private EnvoyProcess(Process process, DirectoryInfo workingDirectory, StreamWriter outputWriter, int ingressPort, int healthPort)
    {
        _process = process;
        _workingDirectory = workingDirectory;
        _outputWriter = outputWriter;
        IngressPort = ingressPort;
        HealthPort = healthPort;
    }

    public int IngressPort { get; }

    /// <summary>The plaintext port the load balancer probes; 200 only while the sidecar is healthy.</summary>
    public int HealthPort { get; }

    /// <summary>
    /// The Unix socket Envoy consults for session admission (M4-11), redirected into the work
    /// directory. A test that wants tunnels admitted starts the sidecar's admission host on this
    /// path; a test that starts nothing there is testing that the node fails closed.
    /// </summary>
    public string AuthzSocketPath => Path.Combine(_workingDirectory.FullName, "authz.sock");

    /// <summary>The socket path a caller can compute before Envoy starts, for the given work directory.</summary>
    public static string AuthzSocketPathFor(DirectoryInfo workingDirectory) =>
        Path.Combine(workingDirectory.FullName, "authz.sock");

    /// <summary>File Envoy's stdout is captured to (its own diagnostics).</summary>
    public string OutputPath => Path.Combine(_workingDirectory.FullName, "envoy.out");

    /// <summary>
    /// The access log carrying hostname telemetry — the file the node sidecar consumes in
    /// production, redirected here so a test run writes nothing outside its temp directory.
    /// </summary>
    public string AccessLogPath => Path.Combine(_workingDirectory.FullName, "envoy-access.log");

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
    /// <param name="requireClientCertificate">
    /// Leave true. Setting it false rewrites <c>require_client_certificate</c> to <c>false</c> in
    /// the copy of the committed config this process runs, which exists for exactly one purpose: a
    /// meta-test proving the client-authentication test would notice if that line were removed from
    /// the real file. It is a named switch rather than a general config-transform hook so the only
    /// property it can weaken is the one the meta-test is about.
    /// </param>
    /// <param name="failureModeAllow">
    /// Leave false. Setting it true rewrites the admission filter's <c>failure_mode_allow</c> to
    /// <c>true</c>, for the same reason and with the same discipline: a meta-test proving the
    /// fail-closed test would notice if the real file stopped failing closed.
    /// </param>
    /// <param name="workingDirectory">
    /// Optional work directory, for a caller that must know the admission socket path before Envoy
    /// starts. Created as a temp directory when not supplied.
    /// </param>
    public static async Task<EnvoyProcess> StartAsync(
        string envoyBinary,
        CertificateAuthority authority,
        string serverName,
        Action<string>? onOutput = null,
        bool requireClientCertificate = true,
        bool failureModeAllow = false,
        DirectoryInfo? workingDirectory = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authority);

        var work = workingDirectory ?? Directory.CreateTempSubdirectory("mina-envoy");
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
        var healthPort = FreePort();
        var adminSocket = Path.Combine(work.FullName, "admin.sock");
        var configPath = Path.Combine(work.FullName, "envoy.yaml");
        File.WriteAllText(configPath, File.ReadAllText(LocateConfig())
            .Replace("/etc/mina/tls", work.FullName, StringComparison.Ordinal)
            .Replace("/var/log/mina/envoy-access.log",
                Path.Combine(work.FullName, "envoy-access.log"), StringComparison.Ordinal)
            .Replace("/run/mina/envoy-admin.sock", adminSocket, StringComparison.Ordinal)
            .Replace("/run/mina-sidecar/authz.sock", AuthzSocketPathFor(work), StringComparison.Ordinal)
            .Replace("port_value: 8443", $"port_value: {ingressPort}", StringComparison.Ordinal)
            .Replace("port_value: 8081", $"port_value: {healthPort}", StringComparison.Ordinal)
            // The only rule relaxed for tests: the destination deny-list refuses loopback, and a
            // test's target server has nowhere else to live. Narrowing the prefix rather than
            // removing the rule keeps the filter, and every other range, exactly as shipped — so a
            // test can still prove that a CONNECT to 169.254.169.254 is refused.
            .Replace("prefix: \"127.\"", "prefix: \"127.128.\"", StringComparison.Ordinal)
            // Rewriting the value, not deleting the line: dropping the line leaves its indentation
            // glued to the next key and Envoy refuses the file as malformed YAML, which would make
            // the meta-test pass for the wrong reason.
            .Replace(
                "require_client_certificate: true",
                $"require_client_certificate: {(requireClientCertificate ? "true" : "false")}",
                StringComparison.Ordinal)
            .Replace(
                "failure_mode_allow: false",
                $"failure_mode_allow: {(failureModeAllow ? "true" : "false")}",
                StringComparison.Ordinal));

        var startInfo = new ProcessStartInfo(envoyBinary)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        startInfo.ArgumentList.Add("-c");
        startInfo.ArgumentList.Add(configPath);
        // Several Envoys run at once when test classes run in parallel; the hot-restart domain
        // socket is keyed on a base id, so without this the second instance dies at startup with
        // "unable to bind domain socket ... errno=98".
        startInfo.ArgumentList.Add("--disable-hot-restart");
        startInfo.ArgumentList.Add("--log-level");
        // MINA_ENVOY_LOG_LEVEL=debug (or trace) when a test needs to see what Envoy actually did.
        startInfo.ArgumentList.Add(Environment.GetEnvironmentVariable("MINA_ENVOY_LOG_LEVEL") is { Length: > 0 } level ? level : "warning");

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
        // Envoy logs to stderr. Discarding it left "exited during startup" with no reason attached.
        process.ErrorDataReceived += (_, e) =>
        {
            if (e.Data is not null)
            {
                lock (writer)
                {
                    writer.WriteLine(e.Data);
                }
            }
        };
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        var envoy = new EnvoyProcess(process, work, writer, ingressPort, healthPort);
        try
        {
            await WaitForReadyAsync(adminSocket, process, cancellationToken).ConfigureAwait(false);
            return envoy;
        }
        catch
        {
            await envoy.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>
    /// Polls the admin <c>/ready</c> endpoint over its Unix socket. The admin interface is not on
    /// TCP in the shipped config — a loopback port would be reachable through the proxy itself —
    /// so the readiness check dials the pipe the same way an operator on the node would.
    /// </summary>
    private static async Task WaitForReadyAsync(string adminSocket, Process process, CancellationToken cancellationToken)
    {
        using var handler = new SocketsHttpHandler
        {
            ConnectCallback = async (_, ct) =>
            {
                var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
                try
                {
                    await socket.ConnectAsync(new UnixDomainSocketEndPoint(adminSocket), ct).ConfigureAwait(false);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            },
        };

        using var http = new HttpClient(handler) { Timeout = TimeSpan.FromMilliseconds(500) };
        var readyUri = new Uri("http://localhost/ready");

        for (var attempt = 0; attempt < 120; attempt++)
        {
            if (process.HasExited)
            {
                var outputPath = Path.Combine(Path.GetDirectoryName(adminSocket)!, "envoy.out");
                var tail = File.Exists(outputPath)
                    ? string.Join(Environment.NewLine, File.ReadAllLines(outputPath).TakeLast(15))
                    : "(no output captured)";
                throw new InvalidOperationException(
                    $"Envoy exited during startup with code {process.ExitCode}.{Environment.NewLine}{tail}");
            }

            try
            {
                using var response = await http.GetAsync(readyUri, cancellationToken).ConfigureAwait(false);
                if (response.IsSuccessStatusCode)
                {
                    return;
                }
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or SocketException)
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

        if (Environment.GetEnvironmentVariable("MINA_ENVOY_KEEP") is "1")
        {
            // Diagnosis: leave the work directory (config, certs, envoy.out, access log) behind.
            Console.Error.WriteLine($"[EnvoyProcess] kept {_workingDirectory.FullName}");
            return ValueTask.CompletedTask;
        }

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
