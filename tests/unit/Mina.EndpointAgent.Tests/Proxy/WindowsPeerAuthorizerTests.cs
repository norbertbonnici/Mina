using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Mina.EndpointAgent.Configuration;
using Mina.EndpointAgent.Proxy;

namespace Mina.EndpointAgent.Tests.Proxy;

/// <summary>
/// Real processes, real loopback sockets, real WMI lookups — no fake for any of it, because the
/// whole point of this class is resolving a live OS connection back to a live OS process and this
/// is exactly the kind of check where a mock would prove the test, not the mechanism (M2-4,
/// THREAT_MODEL B1). Each test spawns a real child process that makes the actual TCP connection
/// under test, with a controlled image path and command line — `powershell.exe`, not the real
/// research browser, but a real process the OS reports on the same way Edge would be.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsPeerAuthorizerTests
{
    // The profile directory the authorizer is configured to expect. It never has to exist on disk:
    // the check compares the --user-data-dir the peer process claims against this, and both sides
    // are resolved as paths rather than touched.
    private const string FakeProfileDirectory = @"C:\Mina\research-profile";

    private static WindowsPeerAuthorizer Build(string imagePath, string profileDirectory) =>
        new(
            Options.Create(new MinaAgentOptions
            {
                ResearchBrowser = new ResearchBrowserOptions
                {
                    ImagePath = imagePath,
                    ProfileDirectory = profileDirectory,
                },
            }),
            NullLogger<WindowsPeerAuthorizer>.Instance);

    /// <summary>
    /// Spawns a real PowerShell process that connects a TcpClient to <paramref name="port"/> and
    /// then sleeps, with <paramref name="trailingArguments"/> appended verbatim to its command line
    /// as real, separate arguments — written exactly as they should appear in what
    /// Win32_Process.CommandLine reports, quoting included. Returns the process and its own resolved
    /// image path (queried back from the OS, not assumed), so a test can configure the authorizer
    /// against ground truth rather than a hardcoded guess at where PowerShell lives here.
    /// </summary>
    private static (Process Process, string ImagePath) SpawnConnectingPeer(int port, string trailingArguments)
    {
        // The script ends on a bare '#', so everything PowerShell appends to it from the remaining
        // command-line arguments lands inside a comment and never runs. That is what lets the flags
        // under test sit on the line as arguments of their own — where Chromium puts them, and
        // where CommandLineToArgvW can see them as switches — rather than buried inside the
        // -Command string. Buried there they are only ever a substring of one argument and are not
        // switches at all, which is why a suite built that way could only exercise substring
        // matching and never noticed it was matching far more than the profile it meant to.
        var script = $"$c = New-Object Net.Sockets.TcpClient('127.0.0.1', {port}); Start-Sleep -Seconds 20 #";
        var psi = new ProcessStartInfo("powershell.exe")
        {
            UseShellExecute = false,
            CreateNoWindow = true,

            // A raw Arguments string, not ArgumentList: ArgumentList re-quotes whatever it is given,
            // and these tests exist to control the exact bytes Win32_Process.CommandLine reports —
            // including the quoting real Chromium emits for its network-service subprocess.
            Arguments = $"-NoProfile -NonInteractive -Command \"{script}\" {trailingArguments}",
        };

        var process = Process.Start(psi) ?? throw new InvalidOperationException("Could not start powershell.exe.");

        // MainModule can come back null immediately after Start() -- the OS has not finished
        // populating the process's module list yet, a race that only actually shows up under real
        // system load (never once in an isolated run of this test, reliably under the full suite's
        // parallelism). A short retry, not a longer one-shot wait: this is a startup race, not a
        // slow operation.
        string? imagePath = null;
        for (var attempt = 0; attempt < 20 && imagePath is null; attempt++)
        {
            try
            {
                imagePath = process.MainModule?.FileName;
            }
            catch (Win32Exception)
            {
                // Same race, different failure shape: MainModule can throw rather than return null
                // while the process is still initializing.
            }

            if (imagePath is null)
            {
                Thread.Sleep(50);
            }
        }

        if (imagePath is null)
        {
            process.Kill(entireProcessTree: true);
            throw new InvalidOperationException("Could not resolve the spawned process's own image path.");
        }

        return (process, imagePath);
    }

    private static async Task<Socket> AcceptOneConnectionAsync(TcpListener listener, TimeSpan timeout)
    {
        using var cts = new CancellationTokenSource(timeout);
        var accepted = await listener.AcceptSocketAsync(cts.Token);
        return accepted;
    }

    [WindowsOnlyFact]
    public async Task Admits_a_connection_whose_owning_process_matches_the_configured_image_and_profile()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var (peer, imagePath) = SpawnConnectingPeer(port, $"--user-data-dir={FakeProfileDirectory}");
        try
        {
            using var accepted = await AcceptOneConnectionAsync(listener, TimeSpan.FromSeconds(15));
            var authorizer = Build(imagePath, FakeProfileDirectory);

            var authorized = await authorizer.AuthorizeAsync(accepted, CancellationToken.None);

            Assert.True(authorized);
        }
        finally
        {
            peer.Kill(entireProcessTree: true);
            listener.Stop();
        }
    }

    [WindowsOnlyFact]
    public async Task Admits_a_connection_whose_profile_directory_claim_is_quoted()
    {
        // Found live 2026-09-05 against a real deployment: the socket that actually owns loopback
        // traffic is Chromium's network-service utility subprocess, not the main browser process,
        // and that subprocess re-serialises this flag as --user-data-dir="C:\..." (quoted) even
        // though the main process itself was launched with the same value unquoted. A bare
        // substring check against the unquoted form refused every real connection -- this suite's
        // own simulated command line never happened to include the quoted form, which is exactly
        // why it went uncaught until a real browser exercised it.
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var (peer, imagePath) = SpawnConnectingPeer(port, $"--user-data-dir=\"{FakeProfileDirectory}\"");
        try
        {
            using var accepted = await AcceptOneConnectionAsync(listener, TimeSpan.FromSeconds(15));
            var authorizer = Build(imagePath, FakeProfileDirectory);

            var authorized = await authorizer.AuthorizeAsync(accepted, CancellationToken.None);

            Assert.True(authorized);
        }
        finally
        {
            peer.Kill(entireProcessTree: true);
            listener.Stop();
        }
    }

    /// <summary>
    /// The four ways a wrong profile directory could satisfy a substring check on the raw command
    /// line. Each is a real "ride the tunnel" attempt: the attacker runs the configured research
    /// browser image — which anyone who can run Edge can do — so the image-path check passes, and
    /// only this check stands between them and the analyst's tunnel.
    /// </summary>
    public static TheoryData<string, string> ProfileClaimsThatMustBeRefused() => new()
    {
        // A sibling directory the expected path is a prefix of. Quoted, because that is the form
        // Chromium's network-service subprocess actually emits.
        { "a sibling directory", $"--user-data-dir=\"{FakeProfileDirectory}-evil\"" },

        // The expected text carried inside a different switch's value, with the real profile
        // directory elsewhere on the line.
        {
            "the expected text inside another switch",
            $"--load-extension=\"--user-data-dir={FakeProfileDirectory}\" --user-data-dir=C:\\Evil"
        },

        // A traversal that starts inside the expected directory and leaves it.
        { "a traversal out of the profile", $"--user-data-dir={FakeProfileDirectory}\\..\\elsewhere" },

        // The expected directory present, but a second claim after it. Refused without this having
        // to agree with Chromium about which of two switches wins.
        {
            "a second claim alongside the expected one",
            $"--user-data-dir={FakeProfileDirectory} --user-data-dir=C:\\Evil"
        },
    };

    [WindowsOnlyTheory]
    [MemberData(nameof(ProfileClaimsThatMustBeRefused))]
    public async Task Refuses_the_right_image_whose_profile_claim_only_resembles_the_configured_one(
        string because, string trailingArguments)
    {
        Assert.False(string.IsNullOrEmpty(because));

        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var (peer, imagePath) = SpawnConnectingPeer(port, trailingArguments);
        try
        {
            using var accepted = await AcceptOneConnectionAsync(listener, TimeSpan.FromSeconds(15));
            var authorizer = Build(imagePath, FakeProfileDirectory);

            var authorized = await authorizer.AuthorizeAsync(accepted, CancellationToken.None);

            Assert.False(authorized);
        }
        finally
        {
            peer.Kill(entireProcessTree: true);
            listener.Stop();
        }
    }

    [WindowsOnlyFact]
    public async Task Refuses_a_peer_that_claims_no_profile_directory_at_all()
    {
        // The research browser is always launched with --user-data-dir, so a line without one is not
        // a default to honour: it is a process that never made the claim being checked.
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var (peer, imagePath) = SpawnConnectingPeer(port, "--no-first-run");
        try
        {
            using var accepted = await AcceptOneConnectionAsync(listener, TimeSpan.FromSeconds(15));
            var authorizer = Build(imagePath, FakeProfileDirectory);

            var authorized = await authorizer.AuthorizeAsync(accepted, CancellationToken.None);

            Assert.False(authorized);
        }
        finally
        {
            peer.Kill(entireProcessTree: true);
            listener.Stop();
        }
    }

    [WindowsOnlyFact]
    public async Task Refuses_the_right_image_with_the_wrong_profile_directory()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var (peer, imagePath) = SpawnConnectingPeer(port, @"--user-data-dir=C:\Some\Other\Profile");
        try
        {
            using var accepted = await AcceptOneConnectionAsync(listener, TimeSpan.FromSeconds(15));
            // Same real image path as the connecting process -- only the expected profile differs.
            var authorizer = Build(imagePath, FakeProfileDirectory);

            var authorized = await authorizer.AuthorizeAsync(accepted, CancellationToken.None);

            Assert.False(authorized);
        }
        finally
        {
            peer.Kill(entireProcessTree: true);
            listener.Stop();
        }
    }

    [WindowsOnlyFact]
    public async Task Refuses_a_different_image_entirely_even_with_the_right_profile_claim()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var (peer, imagePath) = SpawnConnectingPeer(port, $"--user-data-dir={FakeProfileDirectory}");
        try
        {
            using var accepted = await AcceptOneConnectionAsync(listener, TimeSpan.FromSeconds(15));
            // The authorizer expects a *different* image path than the one that actually connected.
            var authorizer = Build(imagePath + ".not-the-real-one", FakeProfileDirectory);

            var authorized = await authorizer.AuthorizeAsync(accepted, CancellationToken.None);

            Assert.False(authorized);
        }
        finally
        {
            peer.Kill(entireProcessTree: true);
            listener.Stop();
        }
    }

    [WindowsOnlyFact]
    public async Task Refuses_a_non_loopback_peer_without_even_attempting_a_wmi_lookup()
    {
        var authorizer = Build(@"C:\anything.exe", @"C:\anything");
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

        // No connection was ever made, so RemoteEndPoint/LocalEndPoint are unset -- this is the
        // same shape of input LoopbackPeerAuthorizer refuses, and WindowsPeerAuthorizer must refuse
        // it identically rather than throw resolving a WMI query against a socket with no peer.
        var authorized = await authorizer.AuthorizeAsync(socket, CancellationToken.None);

        Assert.False(authorized);
    }

    [WindowsOnlyFact]
    public void Refuses_to_construct_with_an_unset_image_path()
    {
        var options = Options.Create(new MinaAgentOptions
        {
            ResearchBrowser = new ResearchBrowserOptions { ImagePath = "", ProfileDirectory = @"C:\Profile" },
        });

        Assert.Throws<InvalidOperationException>(
            () => new WindowsPeerAuthorizer(options, NullLogger<WindowsPeerAuthorizer>.Instance));
    }

    [WindowsOnlyFact]
    public void Refuses_to_construct_with_an_unset_profile_directory()
    {
        var options = Options.Create(new MinaAgentOptions
        {
            ResearchBrowser = new ResearchBrowserOptions { ImagePath = @"C:\browser.exe", ProfileDirectory = "" },
        });

        Assert.Throws<InvalidOperationException>(
            () => new WindowsPeerAuthorizer(options, NullLogger<WindowsPeerAuthorizer>.Instance));
    }
}
