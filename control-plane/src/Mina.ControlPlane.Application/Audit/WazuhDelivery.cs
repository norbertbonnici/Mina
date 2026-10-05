using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Mina.ControlPlane.Domain.Audit;

namespace Mina.ControlPlane.Application.Audit;

/// <summary>
/// M3-5: delivery of the audit chain to Wazuh. Unset by default, the same posture as
/// <see cref="Telemetry.TelemetryRetentionOptions"/> and <c>OfficeHoursOptions</c> — a delivery
/// target is environment-specific and unknown in dev/test, so the service must not invent one.
/// </summary>
public sealed class WazuhDeliveryOptions
{
    public const string SectionName = "Mina:Wazuh:Delivery";

    /// <summary>
    /// Where delivered events are appended, one JSON object per line (EVENT_SCHEMAS §2), for the
    /// Wazuh agent co-located with this file (ARCHITECTURE §9's "telemetry relay") to tail via its
    /// own <c>ossec.conf</c> localfile JSON monitoring — see <c>integrations/wazuh</c>. Null
    /// disables delivery entirely; the background service still runs but does nothing every tick.
    /// </summary>
    public string? EventFilePath { get; set; }

    /// <summary>Events read from the audit chain per delivery pass.</summary>
    public int BatchSize { get; set; } = 500;

    /// <summary>How often a pass runs.</summary>
    public TimeSpan Interval { get; set; } = TimeSpan.FromSeconds(30);

    public bool IsConfigured => !string.IsNullOrWhiteSpace(EventFilePath);

    public IEnumerable<string> Validate()
    {
        if (BatchSize is <= 0 or > 10_000)
        {
            yield return $"{SectionName}:BatchSize must be between 1 and 10000.";
        }

        if (Interval < TimeSpan.FromSeconds(1))
        {
            yield return $"{SectionName}:Interval must be at least one second.";
        }
    }
}

/// <summary>
/// Where delivered events land. Delivery is at-least-once (EVENT_SCHEMAS §2): implementations must
/// append <paramref name="content"/> durably *before* recording <paramref name="throughSequence"/>
/// as delivered, so a crash between the two re-delivers the same batch next pass rather than losing
/// it. Wazuh de-duplicates on <c>event_id</c>, which is what makes a redelivered duplicate line safe
/// rather than a double alert.
/// </summary>
public interface IWazuhEventSink
{
    Task DeliverAsync(ReadOnlyMemory<byte> content, long throughSequence, CancellationToken cancellationToken);

    /// <summary>The highest sequence already delivered, or null if nothing has been yet.</summary>
    Task<long?> GetLastDeliveredSequenceAsync(CancellationToken cancellationToken);
}

/// <summary>
/// Safe default when no delivery target is configured. <see cref="WazuhDeliveryService"/> checks
/// <see cref="WazuhDeliveryOptions.IsConfigured"/> before ever calling a sink, so these bodies exist
/// only to satisfy the interface, not to be reached.
/// </summary>
public sealed class NullWazuhEventSink : IWazuhEventSink
{
    public Task DeliverAsync(ReadOnlyMemory<byte> content, long throughSequence, CancellationToken cancellationToken) =>
        throw new InvalidOperationException(
            "NullWazuhEventSink.DeliverAsync was called; WazuhDeliveryService should have refused " +
            "to run before reaching a sink with no delivery target configured.");

    public Task<long?> GetLastDeliveredSequenceAsync(CancellationToken cancellationToken) =>
        Task.FromResult<long?>(null);
}

/// <summary>
/// Renders audit events into the wire envelope EVENT_SCHEMAS §2 documents. Deliberately its own
/// renderer, not shared with <see cref="AuditExportFormat"/>: that format's exact bytes are hashed
/// into the WORM anchor chain, so changing it — even to fix a cosmetic mismatch — would invalidate
/// every anchor already written against it. This one carries no such constraint.
/// </summary>
public static class WazuhEventFormat
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);

    public static byte[] Render(IReadOnlyList<AuditEvent> events)
    {
        ArgumentNullException.ThrowIfNull(events);

        var builder = new StringBuilder();
        foreach (var auditEvent in events)
        {
            builder.AppendLine(JsonSerializer.Serialize(new
            {
                schema = "mina.audit.v1",
                event_id = auditEvent.Id,
                event_type = auditEvent.EventType,
                severity = auditEvent.Severity.ToString().ToLowerInvariant(),
                occurred_at = auditEvent.OccurredAt.ToUniversalTime(),
                environment = auditEvent.Environment,
                component = ToWireName(auditEvent.Component),
                region = auditEvent.Region,
                user = auditEvent.UserObjectId is null
                    ? null
                    : new { upn = auditEvent.UserPrincipalName, oid = auditEvent.UserObjectId },
                device = auditEvent.DeviceId is null ? null : new { entra_device_id = auditEvent.DeviceId },
                // session.mode is deliberately omitted, unlike the envelope's own documented shape:
                // it would have to be the session's *current* mode joined in separately, and
                // attaching present-tense state to a historical event would misreport what was true
                // when the event actually happened (a session_started event from before a later
                // suppression would otherwise read as though it started sensitive).
                session = auditEvent.SessionId is null ? null : new { id = auditEvent.SessionId },
                // Already a JSON-encoded string on AuditEvent itself, embedded as a string value
                // here rather than reparsed into a nested object -- the same convention every other
                // existing consumer of this field already relies on (GET /api/audit/recent,
                // AuditExportFormat), so this stays consistent with what is already shipped rather
                // than introducing a second, differently-shaped "data" for this one surface.
                data = auditEvent.Data,
            }, SerializerOptions));
        }

        return Encoding.UTF8.GetBytes(builder.ToString());
    }

    private static string ToWireName(AuditComponent component) => component switch
    {
        AuditComponent.ControlPlane => "control-plane",
        AuditComponent.EgressNode => "egress-node",
        AuditComponent.EndpointAgent => "endpoint-agent",
        AuditComponent.ManagementUi => "management-ui",
        AuditComponent.Platform => "platform",
        _ => throw new ArgumentOutOfRangeException(nameof(component), component, "Unrecognised audit component."),
    };
}

/// <summary>Outcome of one delivery pass.</summary>
public sealed record WazuhDeliveryResult(long FromSequence, long ToSequence, int EventCount)
{
    public static WazuhDeliveryResult Nothing { get; } = new(0, -1, 0);

    public bool DeliveredAnything => EventCount > 0;
}

/// <summary>
/// Forwards new audit events to Wazuh (AC-013, EVENT_SCHEMAS §5). Kept out of the hosted service so
/// the watermark/batching logic is testable without a timer, matching
/// <see cref="Telemetry.TelemetryRetentionService"/>'s own reasoning.
/// </summary>
public sealed class WazuhDeliveryService(
    IAuditEventStore store, IWazuhEventSink sink, IOptions<WazuhDeliveryOptions> options)
{
    private readonly IAuditEventStore _store = store ?? throw new ArgumentNullException(nameof(store));
    private readonly IWazuhEventSink _sink = sink ?? throw new ArgumentNullException(nameof(sink));
    private readonly WazuhDeliveryOptions _options =
        (options ?? throw new ArgumentNullException(nameof(options))).Value;

    public async Task<WazuhDeliveryResult> DeliverAsync(CancellationToken cancellationToken)
    {
        if (!_options.IsConfigured)
        {
            return WazuhDeliveryResult.Nothing;
        }

        var lastDelivered = await _sink.GetLastDeliveredSequenceAsync(cancellationToken).ConfigureAwait(false);
        var from = (lastDelivered ?? -1) + 1;

        var events = await _store.ReadAsync(from, _options.BatchSize, cancellationToken).ConfigureAwait(false);
        if (events.Count == 0)
        {
            return WazuhDeliveryResult.Nothing;
        }

        var content = WazuhEventFormat.Render(events);
        var to = events[^1].Sequence;
        await _sink.DeliverAsync(content, to, cancellationToken).ConfigureAwait(false);

        return new WazuhDeliveryResult(from, to, events.Count);
    }
}
