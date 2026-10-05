using System.Diagnostics;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Mina.EndpointAgent.Configuration;
using Mina.EndpointAgent.Proxy;
using Mina.EndpointAgent.Session;

namespace Mina.EndpointAgent.Tests.Proxy;

/// <summary>
/// Against the real Windows Firewall, not a mock — the same discipline as
/// <see cref="WindowsPeerAuthorizerTests"/> and for the same reason: the whole point of
/// <see cref="WindowsFirewallEnforcer"/> is committing state to the live OS firewall, and a mock
/// would prove the shell-out call was made, not that the rule it produced actually names the right
/// program. Every test targets a throwaway fake image path, never the real research browser's, and
/// each test cleans the real rule up before and after itself so a failed run does not leave stray
/// state on this machine, and so the shared rule name does not let one test's leftovers pass another
/// test for the wrong reason (M2-4, ARCHITECTURE §3.1).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsFirewallEnforcerTests : IAsyncLifetime
{
    private const string FakeImagePath = @"C:\Mina\Test\fake-research-browser.exe";
    private const string OtherFakeImagePath = @"C:\Mina\Test\some-other-binary.exe";

    public Task InitializeAsync() => RemoveRuleIfPresentAsync();

    public Task DisposeAsync() => RemoveRuleIfPresentAsync();

    private static WindowsFirewallEnforcer Build(string imagePath, ITamperReporter? tamperReporter = null) =>
        new(
            Options.Create(new MinaAgentOptions
            {
                ResearchBrowser = new ResearchBrowserOptions
                {
                    ImagePath = imagePath,
                    ProfileDirectory = @"C:\unused",
                },
            }),
            NullLogger<WindowsFirewallEnforcer>.Instance,
            tamperReporter);

    [WindowsOnlyFact]
    public async Task Creates_the_block_rule_when_none_exists_yet()
    {
        Assert.Null(await WaitForRuleProgramAsync(null));
        var reporter = new RecordingTamperReporter();
        var enforcer = Build(FakeImagePath, reporter);

        await enforcer.EnsureAppliedAsync(CancellationToken.None);

        Assert.Equal(FakeImagePath, await WaitForRuleProgramAsync(FakeImagePath));

        // Absence alone is indistinguishable from a fresh install that has never applied the rule
        // yet, so it must not, on its own, read as tamper.
        Assert.Empty(reporter.Reported);
    }

    [WindowsOnlyFact]
    public async Task Leaves_an_already_correct_rule_in_place()
    {
        var enforcer = Build(FakeImagePath);
        await enforcer.EnsureAppliedAsync(CancellationToken.None);

        // A second New-NetFirewallRule with the same -Name fails outright, so this only passes if
        // EnsureAppliedAsync actually recognised the existing rule as already correct rather than
        // blindly re-issuing the create.
        await enforcer.EnsureAppliedAsync(CancellationToken.None);

        Assert.Equal(FakeImagePath, await WaitForRuleProgramAsync(FakeImagePath));
        Assert.Equal(1, await CountRulesAsync());
    }

    [WindowsOnlyFact]
    public async Task Replaces_a_drifted_rule_that_names_the_wrong_program()
    {
        await RunPowerShellAsync(
            $"New-NetFirewallRule -DisplayName 'stale' -Name '{WindowsFirewallEnforcer.RuleName}' "
            + $"-Direction Outbound -Action Block -Program '{OtherFakeImagePath}' -Profile Any -Enabled True");
        Assert.Equal(OtherFakeImagePath, await WaitForRuleProgramAsync(OtherFakeImagePath));
        var reporter = new RecordingTamperReporter();
        var enforcer = Build(FakeImagePath, reporter);

        await enforcer.EnsureAppliedAsync(CancellationToken.None);

        Assert.Equal(FakeImagePath, await WaitForRuleProgramAsync(FakeImagePath));
        Assert.Equal(1, await CountRulesAsync());

        // A rule present under this reserved name but naming something else is a much stronger
        // tamper signal than plain absence (ARCHITECTURE §3.1) -- reported as such.
        var reported = Assert.Single(reporter.Reported);
        Assert.Equal(TamperIndicators.WfpRuleMissing, reported.Indicator);
    }

    [WindowsOnlyFact]
    public void Refuses_to_construct_with_an_unset_image_path()
    {
        var options = Options.Create(new MinaAgentOptions
        {
            ResearchBrowser = new ResearchBrowserOptions { ImagePath = "", ProfileDirectory = @"C:\unused" },
        });

        Assert.Throws<InvalidOperationException>(
            () => new WindowsFirewallEnforcer(options, NullLogger<WindowsFirewallEnforcer>.Instance));
    }

    /// <summary>
    /// Polls until the rule's program reaches <paramref name="expected"/> (null meaning "no rule"),
    /// and returns the last value actually seen so the caller's own assertion produces the failure
    /// message.
    /// </summary>
    /// <remarks>
    /// The firewall's store is eventually consistent and every observation in this class is a
    /// separate <c>powershell.exe</c>: <c>New-NetFirewallRule</c> returns before a fresh process
    /// running <c>Get-NetFirewallRule</c> can see the result, and <c>Remove-</c> likewise. Each
    /// assertion here used to be one instantaneous read with no tolerance for that, which is why
    /// the suite failed at random — three different tests across four runs, never the same one
    /// twice — and only under the full suite's parallelism, never when this class ran alone. Same
    /// race and same remedy as <c>WindowsPeerAuthorizerTests</c>'s retry around
    /// <c>Process.MainModule</c>.
    ///
    /// This waits for a state to arrive; it does not accept a wrong one. A rule that never reaches
    /// the expected program still fails, with the value it was stuck on.
    /// </remarks>
    private static async Task<string?> WaitForRuleProgramAsync(string? expected)
    {
        var deadline = DateTime.UtcNow.AddSeconds(15);
        string? actual;
        do
        {
            actual = await QueryRuleProgramAsync();
            if (string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase))
            {
                return actual;
            }

            await Task.Delay(200);
        }
        while (DateTime.UtcNow < deadline);

        return actual;
    }

    private static async Task<string?> QueryRuleProgramAsync()
    {
        var result = await RunPowerShellCoreAsync(
            $"(Get-NetFirewallRule -Name '{WindowsFirewallEnforcer.RuleName}' -ErrorAction SilentlyContinue "
            + "| Get-NetFirewallApplicationFilter).Program");
        var value = result.StdOut.Trim();
        return result.ExitCode == 0 && value.Length > 0 ? value : null;
    }

    private static async Task<int> CountRulesAsync()
    {
        var result = await RunPowerShellCoreAsync(
            $"@(Get-NetFirewallRule -Name '{WindowsFirewallEnforcer.RuleName}' -ErrorAction SilentlyContinue).Count");
        return result.ExitCode == 0 && int.TryParse(result.StdOut.Trim(), out var count) ? count : 0;
    }

    /// <summary>
    /// Best-effort, deliberately not <see cref="RunPowerShellAsync"/>: <c>-ErrorAction
    /// SilentlyContinue</c> only suppresses the error from the console, it still leaves <c>$?</c>
    /// false, and powershell.exe reports that as process exit code 1 when nothing after it resets
    /// the state -- which is exactly the case here on every run where the rule does not already
    /// exist (the common case). That is not a failure this cleanup step cares about.
    /// </summary>
    private static async Task RemoveRuleIfPresentAsync()
    {
        await RunPowerShellCoreAsync(
            $"Remove-NetFirewallRule -Name '{WindowsFirewallEnforcer.RuleName}' -ErrorAction SilentlyContinue");

        // Wait for the removal to be observable, not just issued. Returning early let the next
        // test's opening precondition see the previous test's rule and fail before it had done
        // anything -- which is exactly how Creates_the_block_rule_when_none_exists_yet failed.
        await WaitForRuleProgramAsync(null);
    }

    private static async Task RunPowerShellAsync(string script)
    {
        var result = await RunPowerShellCoreAsync(script);
        if (result.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"powershell.exe exited {result.ExitCode} running test setup: {result.StdErr.Trim()}");
        }
    }

    private static async Task<(int ExitCode, string StdOut, string StdErr)> RunPowerShellCoreAsync(string script)
    {
        var startInfo = new ProcessStartInfo("powershell.exe")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-NonInteractive");
        startInfo.ArgumentList.Add("-Command");
        startInfo.ArgumentList.Add(script);

        using var process = new Process { StartInfo = startInfo };
        process.Start();
        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        return (process.ExitCode, await stdoutTask, await stderrTask);
    }
}
