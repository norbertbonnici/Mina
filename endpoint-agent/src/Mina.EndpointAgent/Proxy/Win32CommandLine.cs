using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Mina.EndpointAgent.Proxy;

/// <summary>
/// Parses a raw Win32 command line the same way the process that owns it was given its own argv —
/// extracted out of <see cref="WindowsPeerAuthorizer"/>, which built and hardened this once already
/// (see its own remarks: a naive substring match on the raw line was bypassable four different ways,
/// found by review and fixed 2026-09-05), rather than re-deriving command-line parsing a second time
/// for <see cref="BrowserIntegrityMonitor"/>. Both consumers need the identical guarantee: the
/// switch's *value* is compared as a path, not a substring of the whole line.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class Win32CommandLine
{
    /// <summary>
    /// Splits a raw Win32 command line into arguments using <c>CommandLineToArgvW</c> — the same
    /// parser <c>CreateProcess</c>'d programs are given their own argv by, so this reads the line
    /// exactly as the process that owns it did, including Chromium's own quoting and its
    /// backslash-before-quote escaping. Returns null if the OS could not parse it.
    /// </summary>
    public static string[]? Split(string commandLine)
    {
        var argv = CommandLineToArgvW(commandLine, out var count);
        if (argv == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            var arguments = new string[count];
            for (var i = 0; i < count; i++)
            {
                arguments[i] = Marshal.PtrToStringUni(Marshal.ReadIntPtr(argv, i * IntPtr.Size)) ?? string.Empty;
            }

            return arguments;
        }
        finally
        {
            LocalFree(argv);
        }
    }

    /// <summary>
    /// Reduces a path-shaped value to the form two paths can be compared in, or null if it is not a
    /// usable absolute path. Resolving rather than string-comparing is what stops
    /// <c>C:\Mina\research-profile\..\elsewhere</c> passing for the profile it starts inside.
    /// Relative values are refused rather than resolved: they would resolve against this agent's own
    /// working directory, which is not the one the research browser was launched from.
    /// </summary>
    public static string? NormalizeAbsolutePath(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || !Path.IsPathFullyQualified(value))
        {
            return null;
        }

        try
        {
            return Path.TrimEndingDirectorySeparator(Path.GetFullPath(value));
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return null;
        }
    }

    // DllImport rather than LibraryImport: the source-generated marshalling LibraryImport emits
    // requires AllowUnsafeBlocks for the whole project, which is not worth turning on across the
    // agent for two calls. This is also the form TrayIconHost already uses.
    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CommandLineToArgvW(string commandLine, out int numberOfArguments);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr memory);
}
