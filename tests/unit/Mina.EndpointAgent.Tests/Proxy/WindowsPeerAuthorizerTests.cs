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
    // A no-op flag embedded literally in the spawned process's own command line, after a
    // PowerShell comment marker so it does nothing to the script but still appears verbatim in
    // what Win32_Process.CommandLine reports -- the same field WindowsPeerAuthorizer reads.
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
    /// then sleeps, with <paramref name="profileDirectoryClaim"/> embedded as an inert comment in
    /// its own command line. Returns the process and its own resolved image path (queried back
    /// from the OS, not assumed), so a test can configure the authorizer against ground truth
    /// rather than a hardcoded guess at where PowerShell happens to live on this machine.
    /// </summary>
    private static (Process Process, string ImagePath) SpawnConnectingPeer(int port, string profileDirectoryClaim)
    {
        var script = $"$c = New-Object Net.Sockets.TcpClient('127.0.0.1', {port}); Start-Sleep -Seconds 20 "
            + $"# --user-data-dir={profileDirectoryClaim}";
        var psi = new ProcessStartInfo("powershell.exe")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        psi.ArgumentList.Add("-NoProfile");
        psi.ArgumentList.Add("-NonInteractive");
        psi.ArgumentList.Add("-Command");
        psi.ArgumentList.Add(script);

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

        var (peer, imagePath) = SpawnConnectingPeer(port, FakeProfileDirectory);
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
    public async Task Refuses_the_right_image_with_the_wrong_profile_directory()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var (peer, imagePath) = SpawnConnectingPeer(port, @"C:\Some\Other\Profile");
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

        var (peer, imagePath) = SpawnConnectingPeer(port, FakeProfileDirectory);
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
