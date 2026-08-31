using System.Globalization;
using System.Text.RegularExpressions;
using Mina.ControlPlane.Application.Audit;

namespace Mina.ControlPlane.Api.Infrastructure;

/// <summary>
/// Writes audit exports to a directory.
/// </summary>
/// <remarks>
/// This is the development stand-in for the production sink, which writes to an Azure Storage
/// container with an immutability policy. The write-once property is what makes an export an
/// anchor, and a filesystem cannot enforce it — this implementation refuses to overwrite, which
/// stops accidents but not a determined writer. Production must use immutable storage; that is a
/// deployment requirement, not something the application can guarantee.
/// </remarks>
public sealed partial class FileSystemAuditExportSink : IAuditExportSink
{
    private readonly string _root;

    public FileSystemAuditExportSink(string root)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(root);
        _root = root;
        Directory.CreateDirectory(_root);
    }

    public async Task WriteAsync(string name, ReadOnlyMemory<byte> content, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        var path = Path.Combine(_root, name.Replace('/', Path.DirectorySeparatorChar));
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);

        if (File.Exists(path))
        {
            throw new InvalidOperationException($"An export named '{name}' already exists; exports are write-once.");
        }

        // CreateNew fails rather than truncating if the file appeared in between.
        await using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        await stream.WriteAsync(content, cancellationToken).ConfigureAwait(false);
    }

    public Task<long?> GetLastExportedSequenceAsync(CancellationToken cancellationToken)
    {
        if (!Directory.Exists(_root))
        {
            return Task.FromResult<long?>(null);
        }

        long? highest = null;
        foreach (var file in Directory.EnumerateFiles(_root, "audit-*.jsonl", SearchOption.AllDirectories))
        {
            var match = ExportNamePattern().Match(Path.GetFileName(file));
            if (match.Success
                && long.TryParse(match.Groups["to"].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var to)
                && (highest is null || to > highest))
            {
                highest = to;
            }
        }

        return Task.FromResult(highest);
    }

    [GeneratedRegex(@"^audit-(?<from>\d+)-(?<to>\d+)-.*\.jsonl$")]
    private static partial Regex ExportNamePattern();
}
