namespace Mina.EgressNode.Sidecar;

/// <summary>
/// Turns access-log entries into the batch sent upstream, applying the node's local suppression
/// view: for a suppressed session the destination is dropped here and only the counts survive.
/// </summary>
public sealed class TelemetryBatcher(NodeSessionView allowlist, TimeProvider clock)
{
    private readonly NodeSessionView _allowlist = allowlist ?? throw new ArgumentNullException(nameof(allowlist));
    private readonly TimeProvider _clock = clock ?? throw new ArgumentNullException(nameof(clock));
    private readonly List<TelemetryItem> _pending = [];
    private readonly Lock _gate = new();

    public int PendingCount
    {
        get
        {
            lock (_gate)
            {
                return _pending.Count;
            }
        }
    }

    public void Add(AccessLogEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);

        // The destination is dropped before it is ever queued, so a suppressed session's hostnames
        // are not held in memory waiting to be sent. An entry Envoy already redacted (Hostname
        // null) has nothing to drop; this check still runs for the window between a session
        // becoming suppressed and the next admission check, where Envoy may still log a line in full.
        var withhold = entry.Hostname is null || _allowlist.MustWithholdDestination(entry.SessionId);
        var item = new TelemetryItem(
            entry.SessionId,
            _clock.GetUtcNow(),
            withhold ? null : entry.Hostname,
            entry.Port,
            entry.BytesUp,
            entry.BytesDown,
            entry.DurationMs);

        lock (_gate)
        {
            _pending.Add(item);
        }
    }

    /// <summary>Takes everything queued so far, leaving the batcher empty.</summary>
    public IReadOnlyList<TelemetryItem> Drain()
    {
        lock (_gate)
        {
            if (_pending.Count == 0)
            {
                return [];
            }

            var batch = _pending.ToArray();
            _pending.Clear();
            return batch;
        }
    }
}
