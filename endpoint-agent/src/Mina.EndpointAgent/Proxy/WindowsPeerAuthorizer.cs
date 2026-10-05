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
    private const string ProfileDirectorySwitch = "--user-data-dir=";

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

        // Normalised once here so every connection compares like with like, and so a profile
        // directory that could never match any resolved path is a startup failure rather than a
        // proxy that silently refuses everything.
        _expectedProfileDirectory = Win32CommandLine.NormalizeAbsolutePath(browser.ProfileDirectory)
            ?? throw new InvalidOperationException(
                $"{MinaAgentOptions.Section}:ResearchBrowser:ProfileDirectory must be an absolute path "
                + $"(got '{browser.ProfileDirectory}') — it is compared against the --user-data-dir the "
                + "research browser was launched with, which is always fully qualified.");
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

        if (!ClaimsExpectedProfileDirectory(commandLine))
        {
            Log.ProfileDirectoryMismatch(_logger, pid.Value);
            return false;
        }

        return true;
    }

    /// <summary>
    /// True when every <c>--user-data-dir</c> on the peer's command line names the configured
    /// research profile, and there is at least one.
    /// </summary>
    /// <remarks>
    /// The line is split with the same Win32 parser the process itself was launched through, and the
    /// switch's value is then compared as a path. Both halves matter, and a substring check on the
    /// raw line failed at both:
    /// <list type="bullet">
    /// <item>Parsing, not string-matching, is what handles quoting. Found live against a real
    /// browser: the socket that owns loopback traffic belongs to Chromium's network-service utility
    /// subprocess, not the main process, and that subprocess re-serialises the flag as
    /// <c>--user-data-dir="C:\..."</c> even when the main process was launched with the value
    /// unquoted. Stripping every quote first made that match again, but it also merged argument
    /// boundaries, so a quote placed anywhere could manufacture the expected text.</item>
    /// <item>Comparing the value, not a substring of the line, is what makes the match mean
    /// anything. <c>Contains</c> has no argument terminator, so the expected
    /// <c>--user-data-dir=C:\Mina\research-profile</c> was satisfied by
    /// <c>--user-data-dir=C:\Mina\research-profile-evil</c>, and by the text appearing inside some
    /// other switch's value entirely — admitting exactly the "second, differently-profiled instance
    /// of the same binary" case this class exists to close.</item>
    /// </list>
    /// Every occurrence must match, rather than the last one Chromium would win with: that refuses
    /// a line carrying both the expected directory and another without this having to agree with
    /// Chromium's switch-precedence rules. A line with no <c>--user-data-dir</c> at all is refused
    /// too — the browser is launched with one, so its absence is not a default worth honouring.
    /// </remarks>
    private bool ClaimsExpectedProfileDirectory(string? commandLine)
    {
        if (commandLine is null)
        {
            return false;
        }

        var arguments = Win32CommandLine.Split(commandLine);
        if (arguments is null)
        {
            return false;
        }

        var claimed = false;
        foreach (var argument in arguments)
        {
            if (!argument.StartsWith(ProfileDirectorySwitch, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            claimed = true;
            var value = Win32CommandLine.NormalizeAbsolutePath(argument[ProfileDirectorySwitch.Length..]);
            if (value is null
                || !string.Equals(value, _expectedProfileDirectory, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        return claimed;
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
