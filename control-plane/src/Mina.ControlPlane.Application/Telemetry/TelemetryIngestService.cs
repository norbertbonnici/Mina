using Mina.ControlPlane.Domain.Sessions;
using Mina.ControlPlane.Domain.Telemetry;

namespace Mina.ControlPlane.Application.Telemetry;

/// <summary>
/// Accepts hostname telemetry from egress nodes and decides, server-side, what may be recorded.
/// </summary>
/// <remarks>
/// This is where suppression is *enforced* rather than merely requested. A node is told to withhold
/// destinations for a suppressed session, but the guarantee cannot rest on the node obeying: a stale
/// allowlist, a lagging config push or a compromised node would otherwise defeat an approved
/// suppression silently. So every item is re-checked here against the control plane's own view of
/// the session, hostnames for a suppressed session are reduced to counts before anything is stored,
/// and the discrepancy is raised as a critical event (AC-012, threat N5).
/// </remarks>
public sealed class TelemetryIngestService(
    ITelemetryRepository telemetry,
    ISessionRepository sessions,
    ITelemetryAuditSink audit)
{
    private readonly ITelemetryRepository _telemetry = telemetry ?? throw new ArgumentNullException(nameof(telemetry));
    private readonly ISessionRepository _sessions = sessions ?? throw new ArgumentNullException(nameof(sessions));
    private readonly ITelemetryAuditSink _audit = audit ?? throw new ArgumentNullException(nameof(audit));

    public async Task<TelemetryIngestResult> IngestAsync(TelemetryBatch batch, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(batch);
        ArgumentException.ThrowIfNullOrWhiteSpace(batch.Region);

        var recordable = new List<HostnameObservation>();
        var unattributable = 0;
        var aggregated = 0;
        var mismatches = 0;
        var rejected = 0;

        foreach (var group in batch.Items.GroupBy(item => item.SessionId))
        {
            var session = await _sessions.FindAsync(group.Key, cancellationToken).ConfigureAwait(false);
            if (session is null)
            {
                // Nothing to attribute it to, so it cannot be governed — drop rather than store
                // browsing destinations with no accountable owner (AC-009).
                unattributable += group.Count();
                await _audit.UnattributableTelemetryAsync(
                    group.Key, batch.Region, group.Count(), cancellationToken).ConfigureAwait(false);
                continue;
            }

            // A node may only report for sessions in the region it serves. Without this the region
            // is just a label the caller chooses, and one node could write browsing history against
            // another region's analysts.
            if (!string.Equals(session.Region, batch.Region, StringComparison.OrdinalIgnoreCase))
            {
                unattributable += group.Count();
                await _audit.RegionMismatchAsync(
                    session.Id, batch.Region, session.Region, group.Count(), cancellationToken)
                    .ConfigureAwait(false);
                continue;
            }

            if (session.Mode == SessionMode.Sensitive)
            {
                var (count, mismatched) = await AggregateSuppressedAsync(
                    session.Id, batch.Region, group, cancellationToken).ConfigureAwait(false);
                aggregated += count;
                mismatches += mismatched;
                continue;
            }

            foreach (var item in group)
            {
                if (string.IsNullOrWhiteSpace(item.Hostname))
                {
                    // A count with no destination on an unsuppressed session: nothing to record
                    // beyond what the session itself already carries.
                    continue;
                }

                if (item.Hostname!.Length > HostnameObservation.MaxHostnameLength)
                {
                    // Drop the one bad item rather than letting it fail the batch insert. The whole
                    // batch is one unit of work and the node discards a batch it cannot ship, so an
                    // over-length CONNECT authority would otherwise erase every legitimate
                    // observation for that interval — telemetry blinded without an approval.
                    rejected++;
                    continue;
                }

                recordable.Add(HostnameObservation.Record(
                    session.Id, batch.Region, item.OccurredAt, item.Hostname!, item.Port,
                    item.BytesUp, item.BytesDown, item.DurationMs));
            }
        }

        if (recordable.Count > 0)
        {
            await _telemetry.AddHostnamesAsync(recordable, cancellationToken).ConfigureAwait(false);
        }

        return new TelemetryIngestResult(recordable.Count, aggregated, unattributable, mismatches, rejected);
    }

    /// <summary>
    /// Reduces a suppressed session's traffic to counts. Any item that arrived carrying a hostname
    /// is a node still collecting destinations under an approved suppression: the hostname is
    /// discarded here — it is never written anywhere — and the discrepancy is raised.
    /// </summary>
    private async Task<(int Count, int Mismatches)> AggregateSuppressedAsync(
        Guid sessionId, string region, IEnumerable<TelemetryItem> items, CancellationToken cancellationToken)
    {
        var group = items.ToList();
        var mismatched = group.Count(item => !string.IsNullOrWhiteSpace(item.Hostname));

        var summary = SuppressedTrafficSummary.Record(
            sessionId,
            region,
            group.Min(item => item.OccurredAt),
            group.Count,
            group.Sum(item => item.BytesUp + item.BytesDown));

        // Audit first. A node still sending destinations for a suppressed session is threat N5 —
        // the node is collecting what it was told to stop collecting — and the event is the only
        // record that it happened, since the hostnames themselves are discarded. Storing the
        // summary first meant the summary was committed and, if the audit write then failed, the
        // detection was simply lost: an action proceeding unlogged, which is the one thing the
        // audit ordering exists to prevent.
        if (mismatched > 0)
        {
            await _audit.SuppressionMismatchAsync(sessionId, region, mismatched, cancellationToken)
                .ConfigureAwait(false);
        }

        await _telemetry.AddSuppressedSummaryAsync(summary, cancellationToken).ConfigureAwait(false);

        return (group.Count, mismatched);
    }
}
