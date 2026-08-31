using Mina.ControlPlane.Application.Telemetry;

namespace Mina.ControlPlane.Api.Infrastructure;

/// <summary>
/// Raises telemetry security events (EVENT_SCHEMAS §3). The suppression mismatch is a **critical**
/// event: it means a node kept collecting destinations for a session an approver had suppressed.
/// Nothing was stored, but the discrepancy must be investigated rather than absorbed quietly.
/// </summary>
public sealed partial class LoggingTelemetryAuditSink(ILogger<LoggingTelemetryAuditSink> logger) : ITelemetryAuditSink
{
    public Task SuppressionMismatchAsync(
        Guid sessionId, string region, int itemCount, CancellationToken cancellationToken)
    {
        Log.SuppressionMismatch(logger, sessionId, region, itemCount);
        return Task.CompletedTask;
    }

    public Task UnattributableTelemetryAsync(
        Guid sessionId, string region, int itemCount, CancellationToken cancellationToken)
    {
        Log.Unattributable(logger, sessionId, region, itemCount);
        return Task.CompletedTask;
    }

    private static partial class Log
    {
        [LoggerMessage(Level = LogLevel.Critical,
            Message = "sensitive_suppression_mismatch session={SessionId} region={Region} items={ItemCount} " +
                      "— the node sent destinations for a suppressed session; they were discarded, not stored.")]
        public static partial void SuppressionMismatch(ILogger logger, Guid sessionId, string region, int itemCount);

        [LoggerMessage(Level = LogLevel.Warning,
            Message = "telemetry_unattributable session={SessionId} region={Region} items={ItemCount} " +
                      "— no such session; the records were discarded.")]
        public static partial void Unattributable(ILogger logger, Guid sessionId, string region, int itemCount);
    }
}
