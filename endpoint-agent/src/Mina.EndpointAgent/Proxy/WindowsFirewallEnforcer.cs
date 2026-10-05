using System.Diagnostics;
using System.Runtime.Versioning;
using Microsoft.Extensions.Options;
using Mina.EndpointAgent.Configuration;
using Mina.EndpointAgent.Session;

namespace Mina.EndpointAgent.Proxy;

/// <summary>
/// Installs the WFP enforcement ARCHITECTURE §3.1 describes and M1-5 spent this project's
/// Windows-lab time proving the exact enforceable shape of (M2-4): one outbound-block rule scoped
/// to the research browser's own image path, nothing else. That single rule is the whole control —
/// no separate "permit loopback" rule is needed, because <c>Invoke-LoopbackBypassVerification.ps1</c>
/// found live that Windows does not filter loopback traffic through this layer at all, in either
/// direction; the agent's own proxy is reachable precisely because the block never sees it, not
/// because of an exception carved out for it.
/// </summary>
/// <remarks>
/// <para>
/// Persistent, not per-session, on purpose. <c>Invoke-StartupLeakVerification.ps1</c> measured a
/// real gap — packets escaping in the window before a rule applied — which is why ARCHITECTURE §3.1
/// has these rules exist whenever the agent is installed rather than raised per session: a rule
/// applied at session start would reopen exactly the gap that measurement found. Applied once, here,
/// before the protected path is allowed to open, and left in place for the life of the install.
/// </para>
/// <para>
/// Shells out to <c>powershell.exe</c> for <c>New-NetFirewallRule</c>/<c>Get-NetFirewallApplicationFilter</c>
/// rather than the raw WFP API or a hand-written CIM call: this is the exact mechanism M1-5's
/// scripts used to establish that a rule scoped to an image path is the correct, precise control —
/// re-deriving that against the underlying <c>MSFT_NetFirewallRule</c> CIM class turned out not to
/// be a simple property-set-and-commit the way the peer-verification lookups were (rule creation
/// there is a multi-object association, not a flat class), and a security control is not where to
/// trade a proven mechanism for an unproven shortcut.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed partial class WindowsFirewallEnforcer
{
    /// <summary>Stable identifier — survives across restarts and redeploys so this stays idempotent.</summary>
    public const string RuleName = "Mina-ResearchBrowser-C2-Block";

    private const string DisplayName = "Mina research browser network containment (ADR-0001 C2)";

    private readonly string _expectedImagePath;
    private readonly ITamperReporter? _tamperReporter;
    private readonly ILogger<WindowsFirewallEnforcer> _logger;

    public WindowsFirewallEnforcer(
        IOptions<MinaAgentOptions> options, ILogger<WindowsFirewallEnforcer> logger, ITamperReporter? tamperReporter = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _tamperReporter = tamperReporter;

        var imagePath = options.Value.ResearchBrowser.ImagePath;
        if (string.IsNullOrWhiteSpace(imagePath))
        {
            throw new InvalidOperationException(
                $"{MinaAgentOptions.Section}:ResearchBrowser:ImagePath must be set — unset means there is no "
                + "image path to scope the block rule to, and no enforcement at all.");
        }

        _expectedImagePath = imagePath;
    }

    /// <summary>
    /// Confirms the block rule exists and names the right image path, creating or repairing it if
    /// not. Throws if it still cannot be confirmed afterwards — the caller's contract is to treat
    /// that as fatal to starting at all, the same way an unreachable control plane is: a protected
    /// path this agent could not actually confirm is protected is not a protected path.
    /// </summary>
    public async Task EnsureAppliedAsync(CancellationToken cancellationToken)
    {
        var existing = await QueryRuleProgramAsync(cancellationToken).ConfigureAwait(false);
        if (string.Equals(existing, _expectedImagePath, StringComparison.OrdinalIgnoreCase))
        {
            Log.RuleAlreadyCorrect(_logger, RuleName);
            return;
        }

        if (existing is not null)
        {
            // Reconcile rather than trust the name alone: a rule present under the right name but
            // naming the wrong program (a stale install, a moved browser) would otherwise look
            // covered while enforcing nothing real. Same discipline as the on-prem deploy script's
            // own compare-then-mutate fix, not an existence check.
            Log.RuleDrifted(_logger, RuleName, existing, _expectedImagePath);

            // Reported here, not for a rule that is simply absent: absence is indistinguishable
            // from a fresh install that has never applied the rule yet, but a rule present under
            // this reserved name and pointing somewhere else is a much stronger signal that
            // something interfered with it after it was correctly in place (ARCHITECTURE §3.1).
            _tamperReporter?.Report(TamperIndicators.WfpRuleMissing);

            await RunPowerShellAsync(
                $"Remove-NetFirewallRule -Name '{EscapeSingleQuoted(RuleName)}' -ErrorAction SilentlyContinue",
                cancellationToken).ConfigureAwait(false);
        }

        await RunPowerShellAsync(
            "New-NetFirewallRule "
            + $"-DisplayName '{EscapeSingleQuoted(DisplayName)}' "
            + $"-Name '{EscapeSingleQuoted(RuleName)}' "
            + "-Direction Outbound -Action Block "
            + $"-Program '{EscapeSingleQuoted(_expectedImagePath)}' "
            + "-Profile Any -Enabled True",
            cancellationToken).ConfigureAwait(false);

        var confirmed = await QueryRuleProgramAsync(cancellationToken).ConfigureAwait(false);
        if (!string.Equals(confirmed, _expectedImagePath, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"Could not confirm the research-browser firewall block rule after applying it "
                + $"(expected Program '{_expectedImagePath}', found '{confirmed ?? "(none)"}'). Refusing to "
                + "proceed: without this rule, a manually launched research browser has no network "
                + "containment at all.");
        }

        Log.RuleApplied(_logger, RuleName, _expectedImagePath);
    }

    private static async Task<string?> QueryRuleProgramAsync(CancellationToken cancellationToken)
    {
        var script =
            $"(Get-NetFirewallRule -Name '{EscapeSingleQuoted(RuleName)}' -ErrorAction SilentlyContinue "
            + "| Get-NetFirewallApplicationFilter).Program";
        var result = await RunPowerShellCoreAsync(script, cancellationToken).ConfigureAwait(false);
        var value = result.StdOut.Trim();
        return result.ExitCode == 0 && value.Length > 0 ? value : null;
    }

    private static async Task RunPowerShellAsync(string script, CancellationToken cancellationToken)
    {
        var result = await RunPowerShellCoreAsync(script, cancellationToken).ConfigureAwait(false);
        if (result.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"powershell.exe exited {result.ExitCode} applying the firewall rule: {result.StdErr.Trim()}");
        }
    }

    private static async Task<(int ExitCode, string StdOut, string StdErr)> RunPowerShellCoreAsync(
        string script, CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo("powershell.exe")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        // Each element is its own argv entry (ProcessStartInfo handles Win32 command-line quoting),
        // so the script text below only needs PowerShell-level quoting, not shell-level escaping.
        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-NonInteractive");
        startInfo.ArgumentList.Add("-ExecutionPolicy");
        startInfo.ArgumentList.Add("Bypass");
        startInfo.ArgumentList.Add("-Command");
        startInfo.ArgumentList.Add(script);

        using var process = new Process { StartInfo = startInfo };
        process.Start();
        var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        return (process.ExitCode, await stdoutTask.ConfigureAwait(false), await stderrTask.ConfigureAwait(false));
    }

    /// <summary>PowerShell single-quoted-string escaping: a literal quote is written doubled.</summary>
    private static string EscapeSingleQuoted(string value) => value.Replace("'", "''", StringComparison.Ordinal);

    private static partial class Log
    {
        [LoggerMessage(Level = LogLevel.Information,
            Message = "Firewall rule '{RuleName}' already blocks the configured research-browser image path.")]
        public static partial void RuleAlreadyCorrect(ILogger logger, string ruleName);

        [LoggerMessage(Level = LogLevel.Warning,
            Message = "Firewall rule '{RuleName}' named a different program ('{ActualProgram}') than configured "
                + "('{ExpectedProgram}'); replacing it.")]
        public static partial void RuleDrifted(ILogger logger, string ruleName, string actualProgram, string expectedProgram);

        [LoggerMessage(Level = LogLevel.Information,
            Message = "Applied firewall rule '{RuleName}', blocking all outbound traffic for '{ImagePath}' except loopback.")]
        public static partial void RuleApplied(ILogger logger, string ruleName, string imagePath);
    }
}
