using Microsoft.Extensions.Options;

namespace Mina.EgressNode.Sidecar;

/// <summary>
/// Keeps the node's suppression view current. If a refresh fails the previous view is kept — and,
/// because an unknown session is treated as suppressed, a node that has never managed to fetch the
/// list withholds destinations entirely rather than logging them by default.
/// </summary>
internal sealed partial class AllowlistRefreshService(
    ControlPlaneNodeClient client,
    SuppressionAllowlist allowlist,
    IOptions<SidecarOptions> options,
    TimeProvider clock,
    ILogger<AllowlistRefreshService> logger) : BackgroundService
{
    private readonly SidecarOptions _options = options.Value;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var sessions = await client.GetSessionsAsync(_options.Region, stoppingToken).ConfigureAwait(false);
                allowlist.Update(sessions);

                var suppressed = sessions.Count(session => session.Suppressed);
                Log.Refreshed(logger, sessions.Count, suppressed);
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException
                                       && !stoppingToken.IsCancellationRequested)
            {
                Log.RefreshFailed(logger, ex.Message);
            }

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

    private static partial class Log
    {
        [LoggerMessage(Level = LogLevel.Debug,
            Message = "Allowlist refreshed: {SessionCount} session(s), {SuppressedCount} suppressed.")]
        public static partial void Refreshed(ILogger logger, int sessionCount, int suppressedCount);

        [LoggerMessage(Level = LogLevel.Warning,
            Message = "Allowlist refresh failed ({Reason}); keeping the previous view and withholding " +
                      "destinations for sessions not in it.")]
        public static partial void RefreshFailed(ILogger logger, string reason);
    }
}
