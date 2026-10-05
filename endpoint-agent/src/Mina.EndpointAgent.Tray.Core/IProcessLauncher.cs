using System.Diagnostics;

namespace Mina.EndpointAgent.Tray;

/// <summary>
/// Starts a process. Abstracted so <see cref="ResearchBrowserLauncher"/>'s own logic — which flags
/// get built, in what order, with what substitutions — is under test without actually spawning a
/// real browser (or anything at all) during a test run.
/// </summary>
public interface IProcessLauncher
{
    void Start(string fileName, IReadOnlyList<string> arguments);
}

/// <summary>Production launcher. Thin on purpose: nothing here is worth testing beyond what the real OS does.</summary>
public sealed class RealProcessLauncher : IProcessLauncher
{
    public void Start(string fileName, IReadOnlyList<string> arguments)
    {
        var startInfo = new ProcessStartInfo(fileName) { UseShellExecute = false };
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        Process.Start(startInfo);
    }
}
