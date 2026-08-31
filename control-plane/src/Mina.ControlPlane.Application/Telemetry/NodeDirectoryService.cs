using Mina.ControlPlane.Domain.Sessions;

namespace Mina.ControlPlane.Application.Telemetry;

/// <summary>
/// Tells an egress node which sessions it may serve and which of them are suppressed.
/// </summary>
/// <remarks>
/// The node uses this twice over: to refuse tunnels whose session has ended or been revoked, and to
/// withhold destinations for suppressed sessions at the point of collection. Neither is the
/// guarantee — the egress still authenticates every tunnel by certificate, and the control plane
/// re-checks suppression on ingest — but acting on it promptly is what keeps the window between a
/// decision and its effect short.
/// </remarks>
public sealed class NodeDirectoryService(ISessionQueries sessions, TimeProvider clock)
{
    private readonly ISessionQueries _sessions = sessions ?? throw new ArgumentNullException(nameof(sessions));
    private readonly TimeProvider _clock = clock ?? throw new ArgumentNullException(nameof(clock));

    public async Task<IReadOnlyList<NodeSessionEntry>> ListAsync(string region, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(region);

        var active = await _sessions.ListActiveAsync(_clock.GetUtcNow(), cancellationToken).ConfigureAwait(false);
        return
        [
            .. active
                .Where(session => string.Equals(session.Region, region, StringComparison.OrdinalIgnoreCase))
                .Select(session => new NodeSessionEntry(
                    session.Id, session.Mode == SessionMode.Sensitive, session.LeaseExpiresAt))
        ];
    }
}
