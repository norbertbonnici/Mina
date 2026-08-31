using System.Collections.Concurrent;

namespace Mina.EgressNode.Sidecar;

/// <summary>
/// The node's local view of which sessions are suppressed, refreshed from the control plane.
/// </summary>
/// <remarks>
/// Applying it here is the *first* line of enforcement: destinations for a suppressed session are
/// dropped before they ever leave the node. It is not the guarantee — this view can be stale, and a
/// compromised node could ignore it entirely — which is why the control plane re-checks every item
/// on ingest and raises a critical event when one arrives it should not have (threat N5). When the
/// list cannot be refreshed, the node withholds destinations for sessions it is unsure about rather
/// than assuming they are unsuppressed.
/// </remarks>
public sealed class SuppressionAllowlist
{
    private readonly ConcurrentDictionary<Guid, bool> _suppressed = new();
    private bool _loaded;

    /// <summary>Replaces the view with a freshly fetched one.</summary>
    public void Update(IEnumerable<NodeSession> sessions)
    {
        ArgumentNullException.ThrowIfNull(sessions);

        var next = sessions.ToDictionary(s => s.SessionId, s => s.Suppressed);
        foreach (var key in _suppressed.Keys.Where(key => !next.ContainsKey(key)))
        {
            _suppressed.TryRemove(key, out _);
        }

        foreach (var (sessionId, suppressed) in next)
        {
            _suppressed[sessionId] = suppressed;
        }

        _loaded = true;
    }

    /// <summary>
    /// Whether destinations must be withheld for this session. A session the node has never heard
    /// of — or any session at all before the first successful refresh — is treated as suppressed:
    /// withholding a destination is recoverable, recording one that should have been suppressed is
    /// not.
    /// </summary>
    public bool MustWithholdDestination(Guid sessionId) =>
        !_loaded || !_suppressed.TryGetValue(sessionId, out var suppressed) || suppressed;

    public int KnownSessions => _suppressed.Count;
}

/// <summary>A session entry as the control plane reports it.</summary>
public sealed record NodeSession(Guid SessionId, bool Suppressed, DateTimeOffset LeaseExpiresAt);
