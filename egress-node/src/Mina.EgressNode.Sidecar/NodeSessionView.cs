using System.Collections.Concurrent;

namespace Mina.EgressNode.Sidecar;

/// <summary>
/// The node's local view of the sessions it may serve and which of them are suppressed, refreshed
/// from the control plane.
/// </summary>
/// <remarks>
/// <para>
/// The view answers two questions with two different failure postures, and the difference is
/// deliberate.
/// </para>
/// <para>
/// <b>Admission</b> (<see cref="Admit"/>) decides whether Envoy opens a tunnel for a certificate at
/// all. It fails closed: a session the view does not contain, a view that has never been loaded,
/// and a view older than the node is allowed to trust all refuse. This is what makes revocation
/// take effect at the node within a refresh interval instead of a certificate lifetime (M4-11). A
/// view older than <c>maxAge</c> refuses everything — including sessions it still lists — because
/// past that point the node cannot know which of them have since been revoked, and serving a
/// revoked session is the failure this exists to prevent. The trade is availability: a control
/// plane unreachable for longer than <c>maxAge</c> stops research browsing on this node, which is
/// the platform failing closed (CLAUDE.md property 2), not an outage to be worked around here.
/// </para>
/// <para>
/// <b>Suppression</b> (<see cref="MustWithholdDestination"/>) decides whether a destination is
/// dropped from telemetry. It fails safe in the other direction: unknown means withhold, because
/// withholding a destination is recoverable and recording one that should have been suppressed is
/// not. It is the first line of that enforcement, not the guarantee — the control plane re-checks
/// every item on ingest (threat N5).
/// </para>
/// <para>
/// Age is measured on the monotonic clock, not wall time: an NTP step on the node must neither
/// mark a fresh view stale nor hide a stale one. Lease expiry is necessarily wall time, because
/// that is what the control plane issued.
/// </para>
/// </remarks>
public sealed class NodeSessionView
{
    private readonly ConcurrentDictionary<Guid, NodeSession> _sessions = new();
    private volatile bool _loaded;
    private long _lastRefreshTimestamp;
    private long _lastRefreshedAtTicks;

    /// <summary>Wall-clock time of the last successful refresh, for logs and health; null if never.</summary>
    public DateTimeOffset? LastRefreshedAt =>
        _loaded ? new DateTimeOffset(Interlocked.Read(ref _lastRefreshedAtTicks), TimeSpan.Zero) : null;

    /// <summary>Replaces the view with a freshly fetched one.</summary>
    public void Update(IEnumerable<NodeSession> sessions, TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(sessions);
        ArgumentNullException.ThrowIfNull(clock);

        var next = sessions.ToDictionary(s => s.SessionId);
        foreach (var key in _sessions.Keys.Where(key => !next.ContainsKey(key)))
        {
            _sessions.TryRemove(key, out _);
        }

        foreach (var (sessionId, session) in next)
        {
            _sessions[sessionId] = session;
        }

        // Timestamps first, flag last, so a reader that sees _loaded also sees a refresh time.
        Interlocked.Exchange(ref _lastRefreshedAtTicks, clock.GetUtcNow().UtcTicks);
        Interlocked.Exchange(ref _lastRefreshTimestamp, clock.GetTimestamp());
        _loaded = true;
    }

    /// <summary>How long ago the view was last refreshed, or null if never.</summary>
    public TimeSpan? Age(TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(clock);
        return _loaded ? clock.GetElapsedTime(Interlocked.Read(ref _lastRefreshTimestamp)) : null;
    }

    /// <summary>Whether the view is loaded and no older than <paramref name="maxAge"/>.</summary>
    public bool IsFresh(TimeProvider clock, TimeSpan maxAge) => Age(clock) is { } age && age <= maxAge;

    /// <summary>
    /// Whether a tunnel may be opened for this session now. Anything other than
    /// <see cref="Admission.Admitted"/> is a refusal, and the value says why for the log.
    /// </summary>
    public Admission Admit(Guid sessionId, TimeProvider clock, TimeSpan maxAge)
    {
        ArgumentNullException.ThrowIfNull(clock);

        if (!_loaded)
        {
            return Admission.ViewNotLoaded;
        }

        if (!IsFresh(clock, maxAge))
        {
            return Admission.ViewStale;
        }

        if (!_sessions.TryGetValue(sessionId, out var session))
        {
            return Admission.UnknownSession;
        }

        // The control plane only lists sessions whose lease is current, and the certificate
        // expires with the lease, so this rarely decides anything on its own. It is a cheap
        // consistency check on what can change between refreshes, not a control.
        if (session.LeaseExpiresAt <= clock.GetUtcNow())
        {
            return Admission.LeaseLapsed;
        }

        return Admission.Admitted;
    }

    /// <summary>
    /// Whether destinations must be withheld for this session. A session the node has never heard
    /// of — or any session at all before the first successful refresh — is treated as suppressed.
    /// </summary>
    public bool MustWithholdDestination(Guid sessionId) =>
        !_loaded || !_sessions.TryGetValue(sessionId, out var session) || session.Suppressed;

    public int KnownSessions => _sessions.Count;
}

/// <summary>The outcome of an admission check. Only <see cref="Admitted"/> opens a tunnel.</summary>
public enum Admission
{
    Admitted,

    /// <summary>No refresh has ever succeeded; the node does not know any session.</summary>
    ViewNotLoaded,

    /// <summary>The last successful refresh is older than the node is allowed to trust.</summary>
    ViewStale,

    /// <summary>The control plane does not list this session for this region: ended, revoked, or never issued.</summary>
    UnknownSession,

    /// <summary>Listed, but its lease has run out since the view was refreshed.</summary>
    LeaseLapsed,
}

/// <summary>A session entry as the control plane reports it.</summary>
public sealed record NodeSession(Guid SessionId, bool Suppressed, DateTimeOffset LeaseExpiresAt);

/// <summary>Something that can refresh the view on demand, coalescing concurrent requests.</summary>
public interface ISessionViewRefresher
{
    /// <summary>
    /// Refreshes the view now, or joins a refresh already in progress. Completes when that refresh
    /// has finished, successfully or not; never throws for a failed refresh — the view's age is
    /// what reports that.
    /// </summary>
    Task RefreshAsync(CancellationToken cancellationToken);
}
