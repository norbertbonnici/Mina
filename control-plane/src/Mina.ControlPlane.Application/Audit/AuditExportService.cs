using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
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
/// </remarks>
public sealed class AuditExportService(
    IAuditEventStore store,
    IAuditExportSink sink,
    AuditWriter writer,
    IOptions<AuditOptions> options,
    TimeProvider clock)
{
    private const int MaxEventsPerExport = 5000;

    private static readonly JsonSerializerOptions ExportSerializerOptions = new(JsonSerializerDefaults.Web);

    private readonly IAuditEventStore _store = store ?? throw new ArgumentNullException(nameof(store));
    private readonly IAuditExportSink _sink = sink ?? throw new ArgumentNullException(nameof(sink));
    private readonly AuditWriter _writer = writer ?? throw new ArgumentNullException(nameof(writer));
    private readonly AuditOptions _options = (options ?? throw new ArgumentNullException(nameof(options))).Value;
    private readonly TimeProvider _clock = clock ?? throw new ArgumentNullException(nameof(clock));

    public async Task<AuditExportResult> ExportAsync(CancellationToken cancellationToken)
    {
        var lastExported = await _sink.GetLastExportedSequenceAsync(cancellationToken).ConfigureAwait(false);
        var from = (lastExported ?? -1) + 1;

        var events = await _store.ReadAsync(from, MaxEventsPerExport, cancellationToken).ConfigureAwait(false);
        if (events.Count == 0)
        {
            return AuditExportResult.Nothing;
        }

        var content = Render(events);
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

    /// <summary>One JSON object per line, in chain order — the format the anchor is hashed over.</summary>
    private static byte[] Render(IReadOnlyList<AuditEvent> events)
    {
        var builder = new StringBuilder();
        foreach (var auditEvent in events)
        {
            builder.AppendLine(JsonSerializer.Serialize(new
            {
                schema = "mina.audit.v1",
                event_id = auditEvent.Id,
                sequence = auditEvent.Sequence,
                event_type = auditEvent.EventType,
                severity = auditEvent.Severity.ToString().ToLowerInvariant(),
                component = auditEvent.Component.ToString(),
                occurred_at = auditEvent.OccurredAt.ToUniversalTime(),
                environment = auditEvent.Environment,
                region = auditEvent.Region,
                user = auditEvent.UserObjectId is null
                    ? null
                    : new { oid = auditEvent.UserObjectId, upn = auditEvent.UserPrincipalName },
                device = auditEvent.DeviceId is null ? null : new { entra_device_id = auditEvent.DeviceId },
                session = auditEvent.SessionId is null ? null : new { id = auditEvent.SessionId },
                data = auditEvent.Data,
                previous_hash = auditEvent.PreviousHash,
                hash = auditEvent.Hash,
            }, ExportSerializerOptions));
        }

        return Encoding.UTF8.GetBytes(builder.ToString());
    }
}
