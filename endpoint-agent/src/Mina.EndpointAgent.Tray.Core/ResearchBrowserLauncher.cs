using System.Globalization;
using System.Text.Json;

namespace Mina.EndpointAgent.Tray;

/// <summary>
/// The parsed shape of <c>edge-integration/research-browser-flags.json</c>'s
/// <c>researchBrowser.imagePath</c> and <c>launchFlags</c> — the single source of truth for what
/// gets launched, verified behaviourally against Edge Beta by
/// <c>tests/security/windows-enforcement</c> (M1-5). Parsed here rather than re-typed in C#, so a
/// flag change in that file reaches the tray without a code change and without the two ever being
/// able to drift the way <c>MinaAgentOptions.ResearchBrowserOptions</c>'s own remarks warn about.
/// </summary>
public sealed record ResearchBrowserLaunchTemplate(string ImagePath, IReadOnlyList<string> LaunchFlagTemplates)
{
    public static ResearchBrowserLaunchTemplate Parse(string json)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);

        // One exception type for every way this file can be malformed -- a missing property, the
        // wrong JSON type, or invalid JSON outright are all the same problem to a caller: this
        // deployment's copy of the file does not have the shape the launcher needs.
        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;

            var imagePath = root.GetProperty("researchBrowser").GetProperty("imagePath").GetString();
            if (string.IsNullOrWhiteSpace(imagePath))
            {
                throw new FormatException("research-browser-flags.json has no researchBrowser.imagePath.");
            }

            var flags = root.GetProperty("launchFlags").EnumerateArray()
                .Select(element => element.GetString()
                    ?? throw new FormatException("research-browser-flags.json's launchFlags contains a non-string entry."))
                .ToArray();

            return new ResearchBrowserLaunchTemplate(imagePath, flags);
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException)
        {
            throw new FormatException("research-browser-flags.json is not shaped as the launcher expects.", ex);
        }
    }
}

/// <summary>
/// Launches the research browser exactly as ARCHITECTURE §3.1's decided session-0 answer assigns
/// to the tray: locked flags from signed code, pinned to whatever port the agent's proxy is
/// actually listening on. <paramref name="profileDirectory"/> must match the agent's own
/// <c>Mina:Agent:ResearchBrowser:ProfileDirectory</c> exactly — that is what
/// <c>WindowsPeerAuthorizer</c> checks a connecting process's actual command line against, so a
/// mismatch here means the very browser this launches is refused by the controls meant to admit it.
/// </summary>
public sealed class ResearchBrowserLauncher(
    ResearchBrowserLaunchTemplate template, string profileDirectory, IProcessLauncher processLauncher)
{
    public void Launch(int proxyPort)
    {
        if (proxyPort <= 0)
        {
            throw new InvalidOperationException(
                "Cannot launch the research browser without a live proxy port.");
        }

        var arguments = template.LaunchFlagTemplates
            .Select(flag => flag
                .Replace("{ResearchProfileDir}", profileDirectory, StringComparison.Ordinal)
                .Replace("{AgentProxyPort}", proxyPort.ToString(CultureInfo.InvariantCulture), StringComparison.Ordinal))
            .ToArray();

        processLauncher.Start(template.ImagePath, arguments);
    }
}
