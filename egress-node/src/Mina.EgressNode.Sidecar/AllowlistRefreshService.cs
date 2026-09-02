using Microsoft.Extensions.Options;

namespace Mina.EgressNode.Sidecar;

/// <summary>
/// Keeps the node's session view current, on a timer and on demand.
/// </summary>
/// <remarks>
/// <para>
/// A failed refresh keeps the previous view and is logged; it does not stop the host. Since M4-11
/// this process is load-bearing for every tunnel on the node, so an exception escaping here would
/// turn a malformed response from the published endpoint — a proxy's maintenance page, say — into
/// a node that restarts in a loop and admits nobody. Fail closed is the view's job, by ageing out;
/// it is not this loop's job to crash.
/// </para>
/// <para>
/// On-demand refreshes are coalesced: any number of callers arriving while one is in flight join
/// it rather than starting their own, so a burst of unknown sessions costs one request to the
/// control plane, not one per tunnel.
/// </para>
/// </remarks>
public sealed partial class AllowlistRefreshService(
    ControlPlaneNodeClient client,
    NodeSessionView view,
    IOptions<SidecarOptions> options,
    TimeProvider clock,
    ILogger<AllowlistRefreshService> logger) : BackgroundService, ISessionViewRefresher
{
    private readonly SidecarOptions _options = options.Value;
    private readonly Lock _gate = new();
    private Task? _inFlight;

    public Task RefreshAsync(CancellationToken cancellationToken)
    {
        Task refresh;
        lock (_gate)
        {
            if (_inFlight is null || _inFlight.IsCompleted)
            {
                // Not tied to the caller's token: a refresh other callers have joined must not be
                // cancelled because the first of them gave up.
                _inFlight = RefreshOnceAsync(CancellationToken.None);
            }

            refresh = _inFlight;
        }

        return refresh.WaitAsync(cancellationToken);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            await RefreshAsync(stoppingToken).ConfigureAwait(false);

            try
            {
                await Task.Delay(_options.AllowlistRefreshInterval, clock, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    private async Task RefreshOnceAsync(CancellationToken cancellationToken)
    {
        try
        {
            var sessions = await client.GetSessionsAsync(_options.Region, cancellationToken).ConfigureAwait(false);
            view.Update(sessions, clock);

            var suppressed = sessions.Count(session => session.Suppressed);
            Log.Refreshed(logger, sessions.Count, suppressed);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log.RefreshFailed(logger, ex.GetType().Name, ex.Message);
        }
    }

    private static partial class Log
    {
        [LoggerMessage(Level = LogLevel.Debug,
            Message = "Session view refreshed: {SessionCount} session(s), {SuppressedCount} suppressed.")]
        public static partial void Refreshed(ILogger logger, int sessionCount, int suppressedCount);

        [LoggerMessage(Level = LogLevel.Warning,
            Message = "Session view refresh failed ({ExceptionType}: {Reason}); keeping the previous view. " +
                      "Admission refuses everything once the view is older than AdmissionMaxViewAge.")]
        public static partial void RefreshFailed(ILogger logger, string exceptionType, string reason);
    }
}
