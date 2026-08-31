using System.Diagnostics.Metrics;

namespace Mina.Observability;

/// <summary>
/// The platform's operational metrics (EVENT_SCHEMAS §5). Every dimension here is a platform fact —
/// region, outcome, reason — never a research destination: what analysts reached belongs to the
/// telemetry store, not to an operational dashboard.
/// </summary>
public sealed class MinaMetrics : IDisposable
{
    public const string MeterName = "Mina.ControlPlane";

    private readonly Meter _meter = new(MeterName);
    private readonly Histogram<double> _sessionEstablishDuration;
    private readonly Counter<long> _sessionEstablishFailures;
    private readonly Histogram<double> _approvalWorkflowDuration;
    private readonly Counter<long> _suppressionMismatches;
    private readonly Counter<long> _telemetryItemsIngested;

    public MinaMetrics()
    {
        _sessionEstablishDuration = _meter.CreateHistogram<double>(
            "mina_session_establish_duration_seconds", "s", "Time to issue a research session.");

        _sessionEstablishFailures = _meter.CreateCounter<long>(
            "mina_session_establish_failures_total", "failures", "Session requests refused or failed.");

        _approvalWorkflowDuration = _meter.CreateHistogram<double>(
            "mina_approval_workflow_duration_seconds", "s",
            "Time from a suppression request being raised to being decided.");

        _suppressionMismatches = _meter.CreateCounter<long>(
            "mina_suppression_mismatches_total", "items",
            "Destinations discarded because a node sent them for a suppressed session.");

        _telemetryItemsIngested = _meter.CreateCounter<long>(
            "mina_telemetry_items_total", "items", "Telemetry items received from egress nodes, by outcome.");
    }

    public void SessionEstablished(string region, TimeSpan duration) =>
        _sessionEstablishDuration.Record(duration.TotalSeconds, new KeyValuePair<string, object?>("region", region));

    public void SessionEstablishFailed(string? region, string reason) =>
        _sessionEstablishFailures.Add(1,
            new KeyValuePair<string, object?>("region", region ?? "unknown"),
            new KeyValuePair<string, object?>("reason", reason));

    public void ApprovalDecided(TimeSpan duration, string outcome) =>
        _approvalWorkflowDuration.Record(duration.TotalSeconds, new KeyValuePair<string, object?>("outcome", outcome));

    public void SuppressionMismatch(string region, int count) =>
        _suppressionMismatches.Add(count, new KeyValuePair<string, object?>("region", region));

    public void TelemetryIngested(string region, string outcome, int count) =>
        _telemetryItemsIngested.Add(count,
            new KeyValuePair<string, object?>("region", region),
            new KeyValuePair<string, object?>("outcome", outcome));

    public void Dispose() => _meter.Dispose();
}
