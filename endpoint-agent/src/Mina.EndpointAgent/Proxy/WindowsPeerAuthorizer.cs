using System.Globalization;
using System.Management;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;
using Microsoft.Extensions.Options;
using Mina.EndpointAgent.Configuration;

namespace Mina.EndpointAgent.Proxy;

/// <summary>
/// The production peer check <see cref="LoopbackPeerAuthorizer"/>'s own doc comment describes and
/// explicitly defers (M2-4, THREAT_MODEL B1 spoof, ARCHITECTURE §3.1): resolves the connecting
/// process's PID from the live TCP connection table, then verifies both its image path and its
/// research profile directory against configuration before admitting it. Neither check alone is
/// the control — M1-5 found live that a WFP rule scoped to image path alone still admits a second,
/// differently-profiled instance of the same binary, which is exactly the "ride the tunnel" case
/// this exists to close.
/// </summary>
/// <remarks>
/// Windows-only, like the rest of what this class checks against (ADR-0001 C2 is a Windows
/// mechanism). Built on WMI/CIM rather than a raw <c>iphlpapi.dll</c>/<c>NtQueryInformationProcess</c>
/// P/Invoke pair: <c>MSFT_NetTCPConnection</c> (the connection-to-PID lookup) and
/// <c>Win32_Process</c> (the PID-to-command-line lookup) are both reachable through the legacy
/// <see cref="ManagementObjectSearcher"/> API — confirmed live against a real loopback connection
/// and this process's own PID before writing this class, not assumed from documentation. A few
/// milliseconds of WMI latency per new connection is a cost worth paying for marshaling nothing by
/// hand.
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed partial class WindowsPeerAuthorizer : IPeerAuthorizer
{
    private readonly string _expectedImagePath;
    private readonly string _expectedProfileDirectory;
    private readonly ILogger<WindowsPeerAuthorizer> _logger;

    public WindowsPeerAuthorizer(IOptions<MinaAgentOptions> options, ILogger<WindowsPeerAuthorizer> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        var browser = options.Value.ResearchBrowser;
        // Fail loud at startup rather than fail closed silently at every connection: an unset
        // expected value would refuse every peer forever, which is correct but is a deployment
        // mistake that should surface immediately, not as a mysteriously unusable proxy.
        if (string.IsNullOrWhiteSpace(browser.ImagePath) || string.IsNullOrWhiteSpace(browser.ProfileDirectory))
        {
            throw new InvalidOperationException(
                $"{MinaAgentOptions.Section}:ResearchBrowser:ImagePath and :ProfileDirectory must both be "
                + "set (research-browser-flags.json's researchBrowser.imagePath and the profile the agent "
                + "launches with) — unset means this authorizer would refuse every connection.");
        }

        _expectedImagePath = browser.ImagePath;
        _expectedProfileDirectory = browser.ProfileDirectory;
    }

    public async ValueTask<bool> AuthorizeAsync(Socket clientSocket, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(clientSocket);

        if (clientSocket.RemoteEndPoint is not IPEndPoint remote || !IPAddress.IsLoopback(remote.Address)
            || clientSocket.LocalEndPoint is not IPEndPoint local)
        {
            return false;
        }

        // From the OS's own connection-table perspective, the *client's* local port is what this
        // server sees as the peer's remote port, and vice versa for this listener's own port.
        var pid = await Task.Run(
            () => ResolveOwningProcessId(remote.Port, local.Port), cancellationToken).ConfigureAwait(false);
        if (pid is null)
        {
            Log.CouldNotResolvePeerProcess(_logger, remote.Port);
            return false;
        }

        var (imagePath, commandLine) = await Task.Run(
            () => ResolveProcessDetails(pid.Value), cancellationToken).ConfigureAwait(false);
        if (imagePath is null)
        {
            // The process that owned this connection a moment ago has already exited, or this
            // agent's own identity cannot query it. Either way there is nothing left to verify.
            Log.CouldNotResolveProcessDetails(_logger, pid.Value);
            return false;
        }

        if (!string.Equals(imagePath, _expectedImagePath, StringComparison.OrdinalIgnoreCase))
        {
            Log.ImagePathMismatch(_logger, pid.Value, imagePath);
            return false;
        }

        // Substring on the actual command line, not an exact-argument parse: Chromium quotes and
        // orders flags in ways not worth reproducing here, and the profile directory value itself
        // is what matters, not its exact position or quoting in the line.
        var expectedFlag = $"--user-data-dir={_expectedProfileDirectory}";
        if (commandLine is null || !commandLine.Contains(expectedFlag, StringComparison.OrdinalIgnoreCase))
        {
            Log.ProfileDirectoryMismatch(_logger, pid.Value);
            return false;
        }

        return true;
    }

    private static int? ResolveOwningProcessId(int peerPort, int listenerPort)
    {
        var scope = new ManagementScope(@"root\StandardCimv2");
        scope.Connect();
        var query = new ObjectQuery(
            "SELECT OwningProcess FROM MSFT_NetTCPConnection WHERE "
            + $"LocalPort={peerPort} AND RemotePort={listenerPort} AND LocalAddress='127.0.0.1'");
        using var searcher = new ManagementObjectSearcher(scope, query);
        foreach (var row in searcher.Get().Cast<ManagementBaseObject>())
        {
            using (row)
            {
                return Convert.ToInt32(row["OwningProcess"], CultureInfo.InvariantCulture);
            }
        }

        return null;
    }

    private static (string? ImagePath, string? CommandLine) ResolveProcessDetails(int pid)
    {
        using var searcher = new ManagementObjectSearcher(
            $"SELECT ExecutablePath, CommandLine FROM Win32_Process WHERE ProcessId={pid}");
        foreach (var row in searcher.Get().Cast<ManagementBaseObject>())
        {
            using (row)
            {
                return ((string?)row["ExecutablePath"], (string?)row["CommandLine"]);
            }
        }

        return (null, null);
    }

    private static partial class Log
    {
        [LoggerMessage(Level = LogLevel.Warning,
            Message = "Refused a loopback connection from port {PeerPort}: could not resolve its owning process.")]
        public static partial void CouldNotResolvePeerProcess(ILogger logger, int peerPort);

        [LoggerMessage(Level = LogLevel.Warning,
            Message = "Refused a loopback connection from pid {Pid}: it exited before its details could be checked.")]
        public static partial void CouldNotResolveProcessDetails(ILogger logger, int pid);

        [LoggerMessage(Level = LogLevel.Warning,
            Message = "Refused a loopback connection from pid {Pid}: image path was '{ActualImagePath}', not the research browser.")]
        public static partial void ImagePathMismatch(ILogger logger, int pid, string actualImagePath);

        [LoggerMessage(Level = LogLevel.Warning,
            Message = "Refused a loopback connection from pid {Pid}: the research browser's own image path, but not its dedicated profile directory.")]
        public static partial void ProfileDirectoryMismatch(ILogger logger, int pid);
    }
}
