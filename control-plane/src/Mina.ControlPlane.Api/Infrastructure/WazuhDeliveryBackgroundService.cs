using Microsoft.Extensions.Options;
using Mina.ControlPlane.Application.Audit;
using Mina.ControlPlane.Domain.Coordination;

namespace Mina.ControlPlane.Api.Infrastructure;

/// <summary>
/// Periodically forwards new audit events to Wazuh (AC-013, M3-5). Mirrors
/// <see cref="AuditExportBackgroundService"/>'s shape deliberately: same lease-guarded single-writer
/// pattern, since two instances delivering the same range would double-write every line to the
/// event file.
/// </summary>
internal sealed partial class WazuhDeliveryBackgroundService(
    IServiceScopeFactory scopeFactory,
    ILogger<WazuhDeliveryBackgroundService> logger,
    TimeProvider clock) : BackgroundService
{
    /// <summary>Comfortably longer than any configured interval floor, so a slow pass keeps its lease.</summary>
    private static readonly TimeSpan LeaseTtl = TimeSpan.FromMinutes(5);

    private const string LeaseName = "wazuh-delivery";

    private static readonly string LeaseOwner = $"{Environment.MachineName}:{Environment.ProcessId}";

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            TimeSpan interval;
            try
            {
                using var scope = scopeFactory.CreateScope();

                var leases = scope.ServiceProvider.GetRequiredService<IBackgroundLeaseStore>();
                if (!await leases.TryAcquireAsync(LeaseName, LeaseOwner, LeaseTtl, stoppingToken)
                        .ConfigureAwait(false))
                {
                    Log.NotTheDeliverer(logger);
                    interval = scope.ServiceProvider.GetRequiredService<IOptions<WazuhDeliveryOptions>>().Value.Interval;
                    if (!await DelayAsync(interval, stoppingToken).ConfigureAwait(false))
                    {
                        break;
                    }

                    continue;
                }

                var deliverer = scope.ServiceProvider.GetRequiredService<WazuhDeliveryService>();
                var result = await deliverer.DeliverAsync(stoppingToken).ConfigureAwait(false);
                if (result.DeliveredAnything)
                {
                    Log.Delivered(logger, result.EventCount, result.FromSequence, result.ToSequence);
                }

                interval = scope.ServiceProvider.GetRequiredService<IOptions<WazuhDeliveryOptions>>().Value.Interval;
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // A delivery failure leaves Wazuh behind by one more pass; it does not lose events
                // (the watermark only advances after a successful append) and the next pass retries
                // from the same point.
                Log.DeliveryFailed(logger, ex.Message);
                interval = TimeSpan.FromSeconds(30);
            }

            if (!await DelayAsync(interval, stoppingToken).ConfigureAwait(false))
            {
                break;
            }
        }
    }

    /// <summary>Waits for the next tick. False when shutdown interrupted it.</summary>
    private async Task<bool> DelayAsync(TimeSpan interval, CancellationToken stoppingToken)
    {
        try
        {
            await Task.Delay(interval, clock, stoppingToken).ConfigureAwait(false);
            return true;
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }

    private static partial class Log
    {
        [LoggerMessage(Level = LogLevel.Information,
            Message = "Delivered {Count} audit event(s) to Wazuh, range={From}..{To}.")]
        public static partial void Delivered(ILogger logger, int count, long from, long to);

        [LoggerMessage(Level = LogLevel.Warning,
            Message = "Wazuh delivery failed ({Reason}); retrying from the same watermark next pass.")]
        public static partial void DeliveryFailed(ILogger logger, string reason);

        [LoggerMessage(Level = LogLevel.Debug,
            Message = "Another instance holds the wazuh-delivery lease; skipping this pass.")]
        public static partial void NotTheDeliverer(ILogger logger);
    }
}
