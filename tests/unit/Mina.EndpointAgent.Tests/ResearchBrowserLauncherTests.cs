using Mina.EndpointAgent.Tray;

namespace Mina.EndpointAgent.Tests;

/// <summary>
/// What the tray actually launches the research browser with (M2-4/ADR-0001 variant C2). The
/// template comes from <c>edge-integration/research-browser-flags.json</c> — the same file
/// <c>WindowsPeerAuthorizer</c>'s configuration must match — so these tests both pin the
/// substitution logic and guard against that file drifting out from under the tray.
/// </summary>
public sealed class ResearchBrowserLauncherTests
{
    private const string SampleJson = """
        {
          "researchBrowser": { "imagePath": "C:\\Program Files (x86)\\Microsoft\\Edge Beta\\Application\\msedge.exe" },
          "launchFlags": [
            "--user-data-dir={ResearchProfileDir}",
            "--proxy-server=http://127.0.0.1:{AgentProxyPort}",
            "--no-first-run"
          ]
        }
        """;

    [Fact]
    public void The_image_path_and_flags_are_parsed()
    {
        var template = ResearchBrowserLaunchTemplate.Parse(SampleJson);

        Assert.Equal(
            "C:\\Program Files (x86)\\Microsoft\\Edge Beta\\Application\\msedge.exe", template.ImagePath);
        Assert.Equal(3, template.LaunchFlagTemplates.Count);
    }

    [Fact]
    public void Launching_substitutes_the_profile_directory_and_port()
    {
        var template = ResearchBrowserLaunchTemplate.Parse(SampleJson);
        var launcher = new ResearchBrowserLauncher(template, @"C:\Mina\ResearchProfile", processLauncher: new RecordingProcessLauncher(out var recorder));

        launcher.Launch(54219);

        Assert.Equal("C:\\Program Files (x86)\\Microsoft\\Edge Beta\\Application\\msedge.exe", recorder.FileName);
        Assert.Equal(
            [
                "--user-data-dir=C:\\Mina\\ResearchProfile",
                "--proxy-server=http://127.0.0.1:54219",
                "--no-first-run",
            ],
            recorder.Arguments);
    }

    [Fact]
    public void Launching_without_a_live_port_is_refused()
    {
        var template = ResearchBrowserLaunchTemplate.Parse(SampleJson);
        var launcher = new ResearchBrowserLauncher(template, @"C:\Mina\ResearchProfile", new RecordingProcessLauncher(out var recorder));

        Assert.Throws<InvalidOperationException>(() => launcher.Launch(0));
        Assert.Null(recorder.FileName);
    }

    [Fact]
    public void A_non_string_flag_entry_is_rejected()
    {
        const string json = """
            {
              "researchBrowser": { "imagePath": "msedge.exe" },
              "launchFlags": ["--ok", 5]
            }
            """;

        Assert.Throws<FormatException>(() => ResearchBrowserLaunchTemplate.Parse(json));
    }

    [Fact]
    public void A_missing_image_path_is_rejected()
    {
        const string json = """{ "researchBrowser": {}, "launchFlags": [] }""";

        Assert.Throws<FormatException>(() => ResearchBrowserLaunchTemplate.Parse(json));
    }

    [Fact]
    public void The_real_checked_in_file_still_parses_and_matches_what_the_agent_checks_a_peer_against()
    {
        // Drift guard: this is the exact file the tray's Mina.EndpointAgent.Tray.csproj copies into
        // its own output directory at build time. If someone edits the JSON shape and forgets this
        // test exists, this is where that surfaces -- rather than only at runtime on a real device.
        var path = FindRepoFile("edge-integration/research-browser-flags.json");
        var template = ResearchBrowserLaunchTemplate.Parse(File.ReadAllText(path));

        Assert.Equal(
            "C:\\Program Files (x86)\\Microsoft\\Edge Beta\\Application\\msedge.exe", template.ImagePath);
        Assert.Contains("--user-data-dir={ResearchProfileDir}", template.LaunchFlagTemplates);
        Assert.Contains("--proxy-server=http://127.0.0.1:{AgentProxyPort}", template.LaunchFlagTemplates);
    }

    private static string FindRepoFile(string repoRelativePath)
    {
        var dir = AppContext.BaseDirectory;
        for (var i = 0; i < 10; i++)
        {
            var candidate = Path.Combine(dir, repoRelativePath);
            if (File.Exists(candidate))
            {
                return candidate;
            }

            dir = Path.GetDirectoryName(dir) ?? throw new DirectoryNotFoundException(
                $"Could not find {repoRelativePath} above {AppContext.BaseDirectory}.");
        }

        throw new DirectoryNotFoundException($"Could not find {repoRelativePath} above {AppContext.BaseDirectory}.");
    }

    private sealed class RecordingProcessLauncher : IProcessLauncher
    {
        private readonly Recorded _recorded;

        public RecordingProcessLauncher(out Recorded recorded) => recorded = _recorded = new Recorded();

        public void Start(string fileName, IReadOnlyList<string> arguments)
        {
            _recorded.FileName = fileName;
            _recorded.Arguments = arguments;
        }
    }

    private sealed class Recorded
    {
        public string? FileName { get; set; }

        public IReadOnlyList<string> Arguments { get; set; } = [];
    }
}
