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

    /// <summary>
    /// C3 retention deleted telemetry (`telemetry_retention_applied`). Routine, so Info — but it is
    /// in the governance trail rather than only the service log, because deletion is the one action
    /// here whose evidence deletes itself: without this event, "the hostnames are gone" and "the
    /// hostnames were never recorded" look identical afterwards.
    /// </summary>
    Task RetentionAppliedAsync(
        DateTimeOffset cutoff, int hostnames, int suppressedSummaries, CancellationToken cancellationToken);

    /// <summary>
    /// A browsing-data review query read C3 (`telemetry_viewed`, M3-8) — threat N10's access-control
    /// mitigation made concrete: this proves *that* hostname telemetry was read and by whom, on every
    /// query, not only when something looks wrong. Never carries a hostname; <paramref name="targetAnalystUpn"/>
    /// is null for a query spanning every analyst, never a wildcard string that could be mistaken for
    /// a real UPN.
    /// </summary>
    Task TelemetryViewedAsync(
        string viewerUpn, string viewerObjectId, string? targetAnalystUpn,
        DateTimeOffset rangeFrom, DateTimeOffset rangeTo, int sessionCount, CancellationToken cancellationToken);
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

    public Task RetentionAppliedAsync(
        DateTimeOffset cutoff, int hostnames, int suppressedSummaries,
        CancellationToken cancellationToken) => Task.CompletedTask;

    public Task TelemetryViewedAsync(
        string viewerUpn, string viewerObjectId, string? targetAnalystUpn,
        DateTimeOffset rangeFrom, DateTimeOffset rangeTo, int sessionCount,
        CancellationToken cancellationToken) => Task.CompletedTask;
}
