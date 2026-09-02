using System.Globalization;
using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Mina.ControlPlane.Domain.Audit;

namespace Mina.ControlPlane.Application.Audit;

/// <summary>Where an export is written. Production uses write-once (immutable) blob storage.</summary>
public interface IAuditExportSink
{
    /// <summary>
    /// Writes one export. Implementations must refuse to overwrite an existing name — an export is
    /// an anchor, and one that can be replaced anchors nothing.
    /// </summary>
    Task WriteAsync(string name, ReadOnlyMemory<byte> content, CancellationToken cancellationToken);

    /// <summary>The highest sequence already exported, so the next export continues from there.</summary>
    Task<long?> GetLastExportedSequenceAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Reads back a previously written export, or null if there is no such name. This is what turns
    /// an export into a usable anchor: without reading it, nothing ever compares the chain against
    /// the copy in write-once storage.
    /// </summary>
    Task<ReadOnlyMemory<byte>?> ReadAsync(string name, CancellationToken cancellationToken);
}

/// <summary>Raised when the audit trail and its anchors disagree in a way that needs a human.</summary>
public sealed class AuditAnchorException : Exception
{
    public AuditAnchorException()
        : base("The audit trail and its anchors disagree.")
    {
    }

    public AuditAnchorException(string message)
        : base(message)
    {
    }

    public AuditAnchorException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>Outcome of an export attempt.</summary>
public sealed record AuditExportResult(long FromSequence, long ToSequence, int EventCount, string ContentHash)
{
    public static AuditExportResult Nothing { get; } = new(0, -1, 0, string.Empty);

    public bool ExportedAnything => EventCount > 0;
}

/// <summary>
/// Copies a range of the audit chain to write-once storage and records the copy's hash back into
/// the chain.
/// </summary>
/// <remarks>
/// This is what makes the hash chain more than self-referential. A privileged writer could rewrite
/// the database and every link in it, but they cannot alter an export already written to immutable
/// storage — so a rewritten chain no longer matches the anchors, and the divergence is evidence.
/// The `audit_export_completed` event carries the range and the content hash, so the anchors are
/// themselves part of the trail.
///
/// Writing anchors is only half of it: something has to read them back and compare. That is
/// <see cref="AuditAnchorVerifier"/>, reported by <c>GET /api/audit/verify</c> alongside — never
/// folded into — the chain result.
/// </remarks>
public sealed class AuditExportService(
    IAuditEventStore store,
    IAuditExportSink sink,
    AuditWriter writer,
    IOptions<AuditOptions> options,
    TimeProvider clock)
{
    private const int MaxEventsPerExport = 5000;

    private readonly IAuditEventStore _store = store ?? throw new ArgumentNullException(nameof(store));
    private readonly IAuditExportSink _sink = sink ?? throw new ArgumentNullException(nameof(sink));
    private readonly AuditWriter _writer = writer ?? throw new ArgumentNullException(nameof(writer));
    private readonly AuditOptions _options = (options ?? throw new ArgumentNullException(nameof(options))).Value;
    private readonly TimeProvider _clock = clock ?? throw new ArgumentNullException(nameof(clock));

    public async Task<AuditExportResult> ExportAsync(CancellationToken cancellationToken)
    {
        var lastExported = await _sink.GetLastExportedSequenceAsync(cancellationToken).ConfigureAwait(false);
        var from = (lastExported ?? -1) + 1;

        // If the store has fewer events than the anchors already cover, events that were exported
        // are no longer in the database. Reading from `from` would simply come back empty and the
        // export would report "nothing to do" — the quietest possible response to evidence that the
        // audit trail has been truncated. Raise instead: the background service logs it, and
        // /api/audit/verify reports the same divergence in detail.
        var tip = await _store.GetTipAsync(cancellationToken).ConfigureAwait(false);
        if (tip.Sequence < from - 1)
        {
            throw new AuditAnchorException(
                $"The audit store ends at sequence {tip.Sequence} but exports already cover up to "
                + $"{from - 1}. Events that were anchored are missing from the store.");
        }

        var events = await _store.ReadAsync(from, MaxEventsPerExport, cancellationToken).ConfigureAwait(false);
        if (events.Count == 0)
        {
            return AuditExportResult.Nothing;
        }

        var content = AuditExportFormat.Render(events);
        var hash = Convert.ToHexStringLower(SHA256.HashData(content));
        var to = events[^1].Sequence;
        var name = string.Create(
            CultureInfo.InvariantCulture,
            $"{_options.Environment}/audit-{from:D12}-{to:D12}-{_clock.GetUtcNow():yyyyMMddTHHmmssZ}.jsonl");

        await _sink.WriteAsync(name, content, cancellationToken).ConfigureAwait(false);

        // The anchor goes back into the chain, so the export itself is auditable and the next
        // verification covers it.
        await _writer.WriteAsync(
            new AuditEventDraft(
                "audit_export_completed",
                AuditSeverity.Info,
                AuditComponent.ControlPlane,
                Data: new { from, to, count = events.Count, contentHash = hash, name }),
            cancellationToken).ConfigureAwait(false);

        return new AuditExportResult(from, to, events.Count, hash);
    }

}
