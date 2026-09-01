namespace Mina.ControlPlane.Application.Telemetry;

/// <summary>Security events raised by telemetry ingest (EVENT_SCHEMAS §3).</summary>
public interface ITelemetryAuditSink
{
    /// <summary>
    /// A node sent destinations for a session the control plane has suppressed
    /// (`sensitive_suppression_mismatch`, **critical**). The hostnames were not stored, but the
    /// node is still collecting them, so this needs investigating rather than logging quietly:
    /// under the approved suppression the analyst was told those destinations would not be recorded.
    /// </summary>
    Task SuppressionMismatchAsync(Guid sessionId, string region, int itemCount, CancellationToken cancellationToken);

    /// <summary>Telemetry arrived that cannot be attributed to a known session.</summary>
    Task UnattributableTelemetryAsync(
        Guid sessionId, string region, int itemCount, CancellationToken cancellationToken);

    /// <summary>
    /// A node submitted telemetry for a session belonging to a different region
    /// (`telemetry_region_mismatch`, **high**). Either a node is misconfigured, or one is
    /// attempting to write browsing history against another region's analysts; the items are
    /// discarded either way.
    /// </summary>
    Task RegionMismatchAsync(
        Guid sessionId, string claimedRegion, string sessionRegion, int itemCount,
        CancellationToken cancellationToken);
}

/// <summary>No-op sink for tests that do not assert on audit.</summary>
public sealed class NullTelemetryAuditSink : ITelemetryAuditSink
{
    public static NullTelemetryAuditSink Instance { get; } = new();

    public Task SuppressionMismatchAsync(
        Guid sessionId, string region, int itemCount, CancellationToken cancellationToken) => Task.CompletedTask;

    public Task UnattributableTelemetryAsync(
        Guid sessionId, string region, int itemCount, CancellationToken cancellationToken) => Task.CompletedTask;

    public Task RegionMismatchAsync(
        Guid sessionId, string claimedRegion, string sessionRegion, int itemCount,
        CancellationToken cancellationToken) => Task.CompletedTask;
}
