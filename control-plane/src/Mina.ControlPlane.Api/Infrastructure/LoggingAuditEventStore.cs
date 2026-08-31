using Mina.ControlPlane.Domain.Audit;

namespace Mina.ControlPlane.Api.Infrastructure;

/// <summary>
/// Logs every event as it is appended, then delegates to the real store. Operational visibility in
/// one place, rather than each sink logging its own — and the log is a convenience, never the
/// record: the durable chain behind this is what the audit trail actually is.
/// </summary>
public sealed partial class LoggingAuditEventStore(
    IAuditEventStore inner, ILogger<LoggingAuditEventStore> logger) : IAuditEventStore
{
    public Task<AuditChainTip> GetTipAsync(CancellationToken cancellationToken) =>
        inner.GetTipAsync(cancellationToken);

    public async Task AppendAsync(AuditEvent auditEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(auditEvent);
        await inner.AppendAsync(auditEvent, cancellationToken).ConfigureAwait(false);
        Log.Appended(logger, auditEvent.EventType, auditEvent.Sequence, auditEvent.Severity, auditEvent.SessionId);
    }

    public Task<IReadOnlyList<AuditEvent>> ReadAsync(
        long fromSequence, int limit, CancellationToken cancellationToken) =>
        inner.ReadAsync(fromSequence, limit, cancellationToken);

    public Task<IReadOnlyList<AuditEvent>> ReadRecentAsync(int limit, CancellationToken cancellationToken) =>
        inner.ReadRecentAsync(limit, cancellationToken);

    private static partial class Log
    {
        [LoggerMessage(Level = LogLevel.Information,
            Message = "audit {EventType} seq={Sequence} severity={Severity} session={SessionId}")]
        public static partial void Appended(
            ILogger logger, string eventType, long sequence, AuditSeverity severity, Guid? sessionId);
    }
}
