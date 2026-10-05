using System.Globalization;
using System.Management;
using System.Runtime.Versioning;
using Microsoft.Extensions.Options;
using Mina.EndpointAgent.Configuration;
using Mina.EndpointAgent.Session;

namespace Mina.EndpointAgent.Proxy;

/// <summary>
/// Closes M2-4's last two tamper indicators (docs/BACKLOG.md): <c>unmanaged_browser_instance</c>
/// (a second, differently-profiled instance of the research browser's own binary — THREAT_MODEL
/// B1's "ride the tunnel" case, caught here as an early warning rather than only at the moment it
/// tries to reach the loopback proxy) and <c>flag_mismatch</c> (the expected profile, but missing
/// one of the leak-defence flags M1-5 found live actually matter). Also re-runs
/// <see cref="WindowsFirewallEnforcer.EnsureAppliedAsync"/> on the same timer, since a rule applied
/// once at startup gives no signal if something removes it later — the other half of the same
/// backlog gap ("continuous, not just startup-time, re-checking of the firewall rule").
/// </summary>
/// <remarks>
/// Real WMI process enumeration, no mock: this exists to see what is actually running on the host,
/// and a fake process list would prove the classification logic, not the thing that actually matters
/// — that a real unmanaged instance or a real missing flag is actually found. Built on
/// <see cref="ManagementObjectSearcher"/> against <c>Win32_Process</c>, the same mechanism
/// <see cref="WindowsPeerAuthorizer"/> already uses and already confirmed reachable live, rather than
/// a second, parallel enumeration approach (<c>System.Diagnostics.Process</c> is not used anywhere
/// else in this codebase).
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed partial class BrowserIntegrityMonitor : BackgroundService
{
    private const string ProfileDirectorySwitch = "--user-data-dir=";
    private const string ProxyServerPrefix = "--proxy-server=";
    private const string ProxyBypassListFlag = "--proxy-bypass-list=<-loopback>";
    private const string WebRtcPolicyFlag = "--webrtc-ip-handling-policy=disable_non_proxied_udp";

    private readonly WindowsFirewallEnforcer _firewallEnforcer;
    private readonly string _expectedImagePath;
    private readonly string _expectedProfileDirectory;
    private readonly TimeSpan _interval;
    private readonly TimeProvider _clock;
    private readonly ILogger<BrowserIntegrityMonitor> _logger;
    private readonly ITamperReporter? _tamperReporter;

    // Per-pid, not per-condition-ever-seen: cleared once a pid is no longer observed, so a standing
    // condition on one long-lived process reports once rather than every tick forever (the same
    // restraint WindowsFirewallEnforcer already applies to its own drift report), while a *later*,
    // genuinely different offending process still gets its own report.
    private readonly HashSet<int> _reportedUnmanaged = [];
    private readonly HashSet<int> _reportedFlagMismatch = [];

    public BrowserIntegrityMonitor(
        WindowsFirewallEnforcer firewallEnforcer,
        IOptions<MinaAgentOptions> options,
        TimeProvider clock,
        ILogger<BrowserIntegrityMonitor> logger,
        ITamperReporter? tamperReporter = null)
    {
        _firewallEnforcer = firewallEnforcer ?? throw new ArgumentNullException(nameof(firewallEnforcer));
        ArgumentNullException.ThrowIfNull(options);
        _clock = clock ?? throw new ArgumentNullException(nameof(clock));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _tamperReporter = tamperReporter;

        var browser = options.Value.ResearchBrowser;
        if (string.IsNullOrWhiteSpace(browser.ImagePath) || string.IsNullOrWhiteSpace(browser.ProfileDirectory))
        {
            throw new InvalidOperationException(
                $"{MinaAgentOptions.Section}:ResearchBrowser:ImagePath and :ProfileDirectory must both be "
                + "set for continuous browser-integrity monitoring (M2-4) to run.");
        }

        _expectedImagePath = browser.ImagePath;
        _expectedProfileDirectory = Win32CommandLine.NormalizeAbsolutePath(browser.ProfileDirectory)
            ?? throw new InvalidOperationException(
                $"{MinaAgentOptions.Section}:ResearchBrowser:ProfileDirectory must be an absolute path "
                + $"(got '{browser.ProfileDirectory}').");

        _interval = options.Value.IntegrityCheckInterval;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await _firewallEnforcer.EnsureAppliedAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // Deliberately not fatal here, unlike the startup call in Program.cs: that call's
                // "no degraded mode" guarantee already ran once before this host started serving
                // anything. A transient failure to reconcile mid-session should not tear down an
                // already-established protected path over what a retry next tick would likely fix —
                // a sustained failure is visible as repeated warnings, not silence.
                Log.FirewallRecheckFailed(_logger, ex.Message);
            }

            try
            {
                await Task.Run(ScanOnce, stoppingToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Log.ProcessScanFailed(_logger, ex.Message);
            }

            try
            {
                await Task.Delay(_interval, _clock, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    /// <summary>
    /// One pass. Every live process running the research browser's own image path is classified:
    /// the expected profile directory and every required flag present (fine, not reported), a
    /// different or missing profile directory (<c>unmanaged_browser_instance</c> — a second instance
    /// of the same binary, not the one the tray launched), or the expected profile with a
    /// leak-defence flag missing (<c>flag_mismatch</c>).
    /// </summary>
    public void ScanOnce()
    {
        var seenPids = new HashSet<int>();

        foreach (var (pid, commandLine) in EnumerateResearchBrowserProcesses(_expectedImagePath))
        {
            seenPids.Add(pid);
            var arguments = Win32CommandLine.Split(commandLine);
            if (arguments is null)
            {
                continue;
            }

            if (!ClaimsExpectedProfileDirectory(arguments))
            {
                if (_reportedUnmanaged.Add(pid))
                {
                    Log.UnmanagedInstanceDetected(_logger, pid);
                    _tamperReporter?.Report(TamperIndicators.UnmanagedBrowserInstance);
                }

                // A mismatched profile's flags are WindowsPeerAuthorizer's concern if it ever tries
                // to reach the loopback proxy, not this check's -- reporting flag_mismatch too would
                // just be a second name for the same finding.
                continue;
            }

            if (!HasRequiredFlags(arguments))
            {
                if (_reportedFlagMismatch.Add(pid))
                {
                    Log.FlagMismatchDetected(_logger, pid);
                    _tamperReporter?.Report(TamperIndicators.FlagMismatch);
                }
            }
        }

        _reportedUnmanaged.RemoveWhere(pid => !seenPids.Contains(pid));
        _reportedFlagMismatch.RemoveWhere(pid => !seenPids.Contains(pid));
    }

    /// <summary>Same parse-then-compare-the-value discipline as <see cref="WindowsPeerAuthorizer"/>'s own check.</summary>
    private bool ClaimsExpectedProfileDirectory(string[] arguments)
    {
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

    /// <summary>
    /// The three flags M1-5 found live actually matter (WFP-bypass-adjacent leak defences), checked
    /// against the parsed argv rather than the raw line -- research-browser-flags.json is this
    /// project's single source of truth for the exact values; these are duplicated here the same way
    /// <see cref="Configuration.ResearchBrowserOptions.ImagePath"/>/<c>ProfileDirectory</c> already
    /// are, since the agent (session 0) does not read that file -- only the tray does.
    /// </summary>
    private static bool HasRequiredFlags(string[] arguments) =>
        Array.Exists(arguments, a => a.StartsWith(ProxyServerPrefix, StringComparison.OrdinalIgnoreCase))
        && Array.Exists(arguments, a => string.Equals(a, ProxyBypassListFlag, StringComparison.OrdinalIgnoreCase))
        && Array.Exists(arguments, a => string.Equals(a, WebRtcPolicyFlag, StringComparison.OrdinalIgnoreCase));

    private static IEnumerable<(int Pid, string CommandLine)> EnumerateResearchBrowserProcesses(
        string expectedImagePath)
    {
        using var searcher = new ManagementObjectSearcher(
            "SELECT ProcessId, ExecutablePath, CommandLine FROM Win32_Process WHERE ExecutablePath IS NOT NULL");
        foreach (var row in searcher.Get().Cast<ManagementBaseObject>())
        {
            using (row)
            {
                var executablePath = (string?)row["ExecutablePath"];
                if (executablePath is null
                    || !string.Equals(executablePath, expectedImagePath, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var pid = Convert.ToInt32(row["ProcessId"], CultureInfo.InvariantCulture);
                yield return (pid, (string?)row["CommandLine"] ?? string.Empty);
            }
        }
    }

    private static partial class Log
    {
        [LoggerMessage(Level = LogLevel.Warning,
            Message = "Could not re-check the WFP containment rule ({Reason}); retrying next pass.")]
        public static partial void FirewallRecheckFailed(ILogger logger, string reason);

        [LoggerMessage(Level = LogLevel.Warning,
            Message = "Could not scan for research-browser processes ({Reason}); retrying next pass.")]
        public static partial void ProcessScanFailed(ILogger logger, string reason);

        [LoggerMessage(Level = LogLevel.Warning,
            Message = "Process {Pid} runs the research browser's image path but not its dedicated profile directory.")]
        public static partial void UnmanagedInstanceDetected(ILogger logger, int pid);

        [LoggerMessage(Level = LogLevel.Warning,
            Message = "Process {Pid} runs the research browser in its dedicated profile but is missing a required leak-defence flag.")]
        public static partial void FlagMismatchDetected(ILogger logger, int pid);
    }
}
