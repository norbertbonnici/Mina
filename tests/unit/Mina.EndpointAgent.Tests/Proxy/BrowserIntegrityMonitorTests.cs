using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Mina.EndpointAgent.Configuration;
using Mina.EndpointAgent.Proxy;
using Mina.EndpointAgent.Session;

namespace Mina.EndpointAgent.Tests.Proxy;

/// <summary>
/// Real WMI process enumeration against real spawned processes, no mock — the whole point of
/// <see cref="BrowserIntegrityMonitor"/> is seeing what is actually running on the host (M2-4).
/// </summary>
/// <remarks>
/// Unlike <c>WindowsPeerAuthorizerTests</c>, which resolves exactly one PID from a live TCP
/// connection, this class enumerates *every* process sharing an image path — and this machine can
/// have several concurrent <c>powershell.exe</c> processes of its own (this whole project session
/// drives one via its own tooling) that would otherwise be indistinguishable noise. Each test copies
/// <c>powershell.exe</c> to a unique temp filename first and spawns that copy, so the monitor's
/// image-path filter matches only the process this test itself started.
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class BrowserIntegrityMonitorTests : IDisposable
{
    private const string ExpectedProfileDirectory = @"C:\Mina\research-profile";
    private const string AllRequiredFlags =
        "--proxy-server=http://127.0.0.1:12345 \"--proxy-bypass-list=<-loopback>\" --webrtc-ip-handling-policy=disable_non_proxied_udp";

    private readonly List<Process> _spawned = [];
    private readonly List<string> _tempFiles = [];

    public void Dispose()
    {
        foreach (var process in _spawned)
        {
            try
            {
                process.Kill(entireProcessTree: true);
                // Kill() does not wait for the OS to actually release the process's own executing
                // image -- deleting the temp copy immediately after can throw
                // UnauthorizedAccessException (a running image, not merely an open file) rather than
                // the more usual IOException a plain open file gives.
                process.WaitForExit(2000);
            }
            catch (InvalidOperationException)
            {
                // Already exited.
            }
        }

        foreach (var path in _tempFiles)
        {
            try
            {
                File.Delete(path);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Best effort; a copy the OS has not finished releasing is not worth failing the test over.
            }
        }
    }

    private static BrowserIntegrityMonitor Build(string imagePath, RecordingTamperReporter reporter) =>
        new(
            new WindowsFirewallEnforcer(
                Options.Create(new MinaAgentOptions
                {
                    ResearchBrowser = new ResearchBrowserOptions { ImagePath = imagePath, ProfileDirectory = ExpectedProfileDirectory },
                }),
                NullLogger<WindowsFirewallEnforcer>.Instance),
            Options.Create(new MinaAgentOptions
            {
                ResearchBrowser = new ResearchBrowserOptions { ImagePath = imagePath, ProfileDirectory = ExpectedProfileDirectory },
            }),
            TimeProvider.System,
            NullLogger<BrowserIntegrityMonitor>.Instance,
            reporter);

    /// <summary>
    /// Copies <c>powershell.exe</c> to a unique temp path and spawns that copy with
    /// <paramref name="trailingArguments"/> appended as real, separate arguments — the same
    /// "arguments of their own, not buried inside -Command" discipline
    /// <c>WindowsPeerAuthorizerTests.SpawnConnectingPeer</c> established, for the same reason: only
    /// arguments on the line the way Chromium would put them are visible to
    /// <c>CommandLineToArgvW</c> as switches at all.
    /// </summary>
    private string SpawnBrowserStandIn(string trailingArguments)
    {
        // Not Environment.ProcessPath -- under the test runner that resolves to the test host
        // itself (e.g. testhost.exe), not PowerShell. The well-known Windows PowerShell location is
        // what needs copying.
        var realPowerShell = Path.Combine(
            Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
        if (!File.Exists(realPowerShell))
        {
            throw new InvalidOperationException($"Expected to find powershell.exe at '{realPowerShell}'.");
        }

        var copyPath = Path.Combine(Path.GetTempPath(), $"mina-test-browser-{Guid.NewGuid():N}.exe");
        File.Copy(realPowerShell, copyPath);
        _tempFiles.Add(copyPath);

        var psi = new ProcessStartInfo(copyPath)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            Arguments = $"-NoProfile -NonInteractive -Command \"Start-Sleep -Seconds 30 #\" {trailingArguments}",
        };

        var process = Process.Start(psi) ?? throw new InvalidOperationException($"Could not start {copyPath}.");
        _spawned.Add(process);

        // Same startup race WindowsPeerAuthorizerTests already found and works around: MainModule
        // (and here, WMI's own view of the process) can lag Process.Start() returning under load.
        for (var attempt = 0; attempt < 20; attempt++)
        {
            try
            {
                if (process.MainModule?.FileName is not null)
                {
                    break;
                }
            }
            catch (Win32Exception)
            {
                // Same race, different failure shape.
            }

            Thread.Sleep(50);
        }

        return copyPath;
    }

    [WindowsOnlyFact]
    public void A_process_with_the_expected_profile_and_every_required_flag_is_not_reported()
    {
        var imagePath = SpawnBrowserStandIn($"--user-data-dir={ExpectedProfileDirectory} {AllRequiredFlags}");
        var reporter = new RecordingTamperReporter();
        var monitor = Build(imagePath, reporter);

        monitor.ScanOnce();

        Assert.Empty(reporter.Reported);
    }

    [WindowsOnlyFact]
    public void A_process_with_a_different_profile_directory_is_reported_as_unmanaged()
    {
        var imagePath = SpawnBrowserStandIn($@"--user-data-dir=C:\Some\Other\Profile {AllRequiredFlags}");
        var reporter = new RecordingTamperReporter();
        var monitor = Build(imagePath, reporter);

        monitor.ScanOnce();

        var reported = Assert.Single(reporter.Reported);
        Assert.Equal(TamperIndicators.UnmanagedBrowserInstance, reported.Indicator);
    }

    [WindowsOnlyFact]
    public void A_process_with_no_profile_directory_claim_at_all_is_reported_as_unmanaged()
    {
        var imagePath = SpawnBrowserStandIn(AllRequiredFlags);
        var reporter = new RecordingTamperReporter();
        var monitor = Build(imagePath, reporter);

        monitor.ScanOnce();

        var reported = Assert.Single(reporter.Reported);
        Assert.Equal(TamperIndicators.UnmanagedBrowserInstance, reported.Indicator);
    }

    public static TheoryData<string, string> MissingRequiredFlags() => new()
    {
        { "the proxy server flag", "\"--proxy-bypass-list=<-loopback>\" --webrtc-ip-handling-policy=disable_non_proxied_udp" },
        { "the proxy bypass list flag", "--proxy-server=http://127.0.0.1:12345 --webrtc-ip-handling-policy=disable_non_proxied_udp" },
        { "the webrtc policy flag", "--proxy-server=http://127.0.0.1:12345 \"--proxy-bypass-list=<-loopback>\"" },
    };

    [WindowsOnlyTheory]
    [MemberData(nameof(MissingRequiredFlags))]
    public void A_process_with_the_expected_profile_but_missing_a_required_flag_is_reported_as_flag_mismatch(
        string because, string flagsPresent)
    {
        Assert.False(string.IsNullOrEmpty(because));
        var imagePath = SpawnBrowserStandIn($"--user-data-dir={ExpectedProfileDirectory} {flagsPresent}");
        var reporter = new RecordingTamperReporter();
        var monitor = Build(imagePath, reporter);

        monitor.ScanOnce();

        var reported = Assert.Single(reporter.Reported);
        Assert.Equal(TamperIndicators.FlagMismatch, reported.Indicator);
    }

    [WindowsOnlyFact]
    public void The_same_offending_process_is_reported_only_once_across_repeated_scans()
    {
        // Proves the dedup itself, independent of any ambient noise on the host: whatever the first
        // scan finds, a second scan of the same still-running process must add nothing new.
        var imagePath = SpawnBrowserStandIn($@"--user-data-dir=C:\Some\Other\Profile {AllRequiredFlags}");
        var reporter = new RecordingTamperReporter();
        var monitor = Build(imagePath, reporter);

        monitor.ScanOnce();
        var afterFirstScan = reporter.Reported.Count;
        Assert.True(afterFirstScan > 0);

        monitor.ScanOnce();

        Assert.Equal(afterFirstScan, reporter.Reported.Count);
    }

    [WindowsOnlyFact]
    public void Refuses_to_construct_with_an_unset_image_path()
    {
        var options = Options.Create(new MinaAgentOptions
        {
            ResearchBrowser = new ResearchBrowserOptions { ImagePath = "", ProfileDirectory = @"C:\Profile" },
        });
        var firewallOptions = Options.Create(new MinaAgentOptions
        {
            ResearchBrowser = new ResearchBrowserOptions { ImagePath = @"C:\browser.exe", ProfileDirectory = @"C:\Profile" },
        });

        Assert.Throws<InvalidOperationException>(() => new BrowserIntegrityMonitor(
            new WindowsFirewallEnforcer(firewallOptions, NullLogger<WindowsFirewallEnforcer>.Instance),
            options,
            TimeProvider.System,
            NullLogger<BrowserIntegrityMonitor>.Instance));
    }

    [WindowsOnlyFact]
    public void Refuses_to_construct_with_an_unset_profile_directory()
    {
        var options = Options.Create(new MinaAgentOptions
        {
            ResearchBrowser = new ResearchBrowserOptions { ImagePath = @"C:\browser.exe", ProfileDirectory = "" },
        });

        Assert.Throws<InvalidOperationException>(() => new BrowserIntegrityMonitor(
            new WindowsFirewallEnforcer(options, NullLogger<WindowsFirewallEnforcer>.Instance),
            options,
            TimeProvider.System,
            NullLogger<BrowserIntegrityMonitor>.Instance));
    }
}
