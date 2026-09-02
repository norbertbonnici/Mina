namespace Mina.TestSupport;

/// <summary>
/// Locates the repository root from a built assembly's location, so hosts and harnesses can find
/// source-tree files (the Envoy config, the API's content root) without hard-coded paths.
/// </summary>
public static class RepoRoot
{
    private const string Marker = "Mina.slnx";

    public static string Find()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(System.IO.Path.Combine(directory.FullName, Marker)))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException(
            $"Could not find the repository root ({Marker}) above {AppContext.BaseDirectory}.");
    }

    /// <summary>Combines path segments onto the repository root.</summary>
    public static string Path(params string[] relativeSegments) =>
        System.IO.Path.Combine([Find(), .. relativeSegments]);
}
