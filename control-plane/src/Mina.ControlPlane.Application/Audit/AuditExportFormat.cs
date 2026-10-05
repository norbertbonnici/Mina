using System.Text;
using System.Text.Json;
using Mina.ControlPlane.Domain.Audit;

namespace Mina.ControlPlane.Application.Audit;

/// <summary>
/// The on-disk form of an audit export: one JSON object per line, in chain order.
/// </summary>
/// <remarks>
/// Shared deliberately between writing an export and verifying one. The anchor is a hash over these
/// exact bytes, so if the two sides rendered independently, a formatting change on one side would
/// make every existing anchor appear broken — an integrity alarm caused by a refactor rather than
/// by tampering, which is the fastest way to teach people to ignore the alarm.
/// </remarks>
public static class AuditExportFormat
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
            }, SerializerOptions));
        }

        return Encoding.UTF8.GetBytes(builder.ToString());
    }
}
