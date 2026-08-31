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
                using var scope = scopeFactory.CreateScope();
                var service = scope.ServiceProvider.GetRequiredService<SensitiveSessionService>();
                var expired = await service.ExpireDueAsync(stoppingToken).ConfigureAwait(false);
                if (expired > 0)
                {
                    Log.Expired(logger, expired);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex) when (ex is InvalidOperationException or TimeoutException)
            {
                // A sweep failure must not kill the loop: the next pass retries, and the window is
                // still enforced because nothing can activate or extend an elapsed approval.
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

    private static partial class Log
    {
        [LoggerMessage(Level = LogLevel.Information,
            Message = "Expired {Count} sensitive-session approval(s) and terminated their sessions.")]
        public static partial void Expired(ILogger logger, int count);

        [LoggerMessage(Level = LogLevel.Warning, Message = "Sensitive-session expiry sweep failed: {Reason}")]
        public static partial void SweepFailed(ILogger logger, string reason);
    }
}
