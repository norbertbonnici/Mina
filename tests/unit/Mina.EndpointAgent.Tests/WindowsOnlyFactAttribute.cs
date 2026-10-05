namespace Mina.EndpointAgent.Tests;

/// <summary>
/// A test that only means anything on Windows, and says so in the results rather than quietly
/// passing elsewhere.
/// </summary>
/// <remarks>
/// The agent's supported deployment is a Windows service, and two of its IPC controls — the pipe
/// DACL and FirstPipeInstance — have no Unix equivalent: .NET backs a named pipe there with a
/// Unix-domain socket, where rebinding an existing name succeeds. Tests for those controls are
/// skipped on CI's Linux hosts and run in the Windows job.
/// </remarks>
public sealed class WindowsOnlyFactAttribute : FactAttribute
{
    public WindowsOnlyFactAttribute()
    {
        if (!OperatingSystem.IsWindows())
        {
            Skip = "Windows-only: the pipe DACL and FirstPipeInstance have no Unix equivalent.";
        }
    }
}

/// <summary>
/// <see cref="WindowsOnlyFactAttribute"/> for a data-driven test — same reasoning, same skip.
/// </summary>
public sealed class WindowsOnlyTheoryAttribute : TheoryAttribute
{
    public WindowsOnlyTheoryAttribute()
    {
        if (!OperatingSystem.IsWindows())
        {
            Skip = "Windows-only: these controls read Win32 process state that has no Unix equivalent.";
        }
    }
}
