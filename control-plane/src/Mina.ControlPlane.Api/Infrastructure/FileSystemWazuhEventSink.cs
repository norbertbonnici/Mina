using System.Globalization;
using Mina.ControlPlane.Application.Audit;

namespace Mina.ControlPlane.Api.Infrastructure;

/// <summary>
/// Appends delivered events to a single file, JSON Lines, for a co-located Wazuh agent to tail
/// (<c>integrations/wazuh</c>'s decoder assumes exactly this: one JSON object per line).
/// </summary>
/// <remarks>
/// Unlike <see cref="FileSystemAuditExportSink"/>, this is not a stand-in for a stricter production
/// backend -- an ever-appended local file genuinely is the production shape for a Wazuh agent's
/// localfile JSON monitoring; the file's own rotation (if any) is an operational/OS concern outside
/// this class, the same way any other log file's rotation is. What this class owns is the
/// at-least-once contract: the watermark file is written only after the content append has
/// completed, so a crash between the two re-delivers the same batch next pass (a harmless duplicate
/// Wazuh de-duplicates on <c>event_id</c>) rather than silently dropping it.
/// </remarks>
public sealed class FileSystemWazuhEventSink : IWazuhEventSink
{
    private readonly string _eventFilePath;
    private readonly string _watermarkPath;

    public FileSystemWazuhEventSink(string eventFilePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(eventFilePath);
        _eventFilePath = eventFilePath;
        _watermarkPath = eventFilePath + ".watermark";

        var directory = Path.GetDirectoryName(Path.GetFullPath(eventFilePath));
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }
    }

    public async Task DeliverAsync(
        ReadOnlyMemory<byte> content, long throughSequence, CancellationToken cancellationToken)
    {
        await using (var stream = new FileStream(
            _eventFilePath, FileMode.Append, FileAccess.Write, FileShare.Read))
        {
            await stream.WriteAsync(content, cancellationToken).ConfigureAwait(false);
        }

        // After the append, per the interface's at-least-once contract. A temp-file-then-rename
        // keeps a concurrent reader of the watermark (there is only ever one writer -- the
        // background service's lease -- but a human inspecting it live is plausible) from ever
        // observing a half-written value.
        var tempPath = _watermarkPath + ".tmp";
        await File.WriteAllTextAsync(
            tempPath, throughSequence.ToString(CultureInfo.InvariantCulture), cancellationToken)
            .ConfigureAwait(false);
        File.Move(tempPath, _watermarkPath, overwrite: true);
    }

    public async Task<long?> GetLastDeliveredSequenceAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(_watermarkPath))
        {
            return null;
        }

        var text = await File.ReadAllTextAsync(_watermarkPath, cancellationToken).ConfigureAwait(false);
        return long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var sequence)
            ? sequence
            : null;
    }
}
