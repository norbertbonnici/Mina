using Mina.ControlPlane.Application.SensitiveSessions;

namespace Mina.ControlPlane.Api.Infrastructure;

/// <summary>
/// Expires suppression approvals whose window has elapsed, and terminates the sessions they belong
/// to (D-06). This runs on a timer rather than relying on the next request touching the record, so
/// an approval cannot outlive its TTL even if the analyst goes idle or the endpoint disappears
/// (FR-011, AC-011).
/// </summary>
internal sealed partial class SensitiveSessionExpiryService(
    IServiceScopeFactory scopeFactory,
    ILogger<SensitiveSessionExpiryService> logger,
    TimeProvider clock) : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(30);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await SweepAsync(scopeFactory, logger, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // Anything short of shutdown is transient as far as this loop is concerned. A hosted
                // service that throws stops the whole host by default, so a narrower filter here
                // meant an ordinary database conflict took session issuance down with it. Crashing
                // buys nothing for a loop that runs again in 30 seconds, and the window stays
                // enforced meanwhile: nothing can activate or extend an elapsed approval.
                Log.SweepFailed(logger, ex.Message);
            }

            try
            {
                await Task.Delay(Interval, clock, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    /// <summary>
    /// Expires every due approval, each in its own scope. The separate scopes are what make the
    /// per-request error handling meaningful: sharing one unit of work would leave a rejected change
    /// tracked, so the first failure would fail every later commit in the same sweep. Without the
    /// isolation, one permanently unexpirable row would hold suppression open past its approved
    /// window for every request queued behind it (AC-011).
    /// </summary>
    internal static async Task<(int Expired, int Failed)> SweepAsync(
        IServiceScopeFactory scopeFactory, ILogger logger, CancellationToken cancellationToken)
    {
        IReadOnlyList<Guid> due;
        using (var scope = scopeFactory.CreateScope())
        {
            due = await scope.ServiceProvider.GetRequiredService<SensitiveSessionService>()
                .ListDueForExpiryAsync(cancellationToken).ConfigureAwait(false);
        }

        var expired = 0;
        var failed = 0;
        foreach (var requestId in due)
        {
            try
            {
                using var scope = scopeFactory.CreateScope();
                var service = scope.ServiceProvider.GetRequiredService<SensitiveSessionService>();
                if (await service.ExpireAsync(requestId, cancellationToken).ConfigureAwait(false))
                {
                    expired++;
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                failed++;
                Log.RequestFailed(logger, requestId, ex.Message);
            }
        }

        if (expired > 0)
        {
            Log.Expired(logger, expired);
        }

        return (expired, failed);
    }

    private static partial class Log
    {
        [LoggerMessage(Level = LogLevel.Information,
            Message = "Expired {Count} sensitive-session approval(s) and terminated their sessions.")]
        public static partial void Expired(ILogger logger, int count);

        [LoggerMessage(Level = LogLevel.Warning, Message = "Sensitive-session expiry sweep failed: {Reason}")]
        public static partial void SweepFailed(ILogger logger, string reason);

        [LoggerMessage(Level = LogLevel.Warning,
            Message = "sensitive_session_expiry_failed request={RequestId} reason={Reason}; retrying next sweep.")]
        public static partial void RequestFailed(ILogger logger, Guid requestId, string reason);
    }
}
