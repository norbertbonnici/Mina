using Mina.ControlPlane.Application.Audit;
using Mina.ControlPlane.Domain.Coordination;

namespace Mina.ControlPlane.Api.Infrastructure;

/// <summary>
/// Periodically anchors the audit chain by exporting everything new to write-once storage. Runs on
/// a timer so the window in which a rewritten chain would go unanchored stays bounded.
/// </summary>
internal sealed partial class AuditExportBackgroundService(
    IServiceScopeFactory scopeFactory,
    ILogger<AuditExportBackgroundService> logger,
    TimeProvider clock) : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromMinutes(15);

    /// <summary>
    /// Comfortably longer than the interval, so the holder keeps the lease across ticks and a
    /// takeover only happens when an instance has actually stopped working rather than merely been
    /// slow.
    /// </summary>
    private static readonly TimeSpan LeaseTtl = TimeSpan.FromMinutes(45);

    private const string LeaseName = "audit-export";

    private static readonly string LeaseOwner =
        $"{Environment.MachineName}:{Environment.ProcessId}";

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = scopeFactory.CreateScope();

                // Only one instance exports. Unlike the expiry sweeps, this is not safe to run
                // twice: both instances compute the same range, one loses the write-once race, and
                // the loss is logged and swallowed. The lease replaces the configuration switch that
                // used to designate an instance, so failover no longer depends on an operator
                // remembering to move a setting.
                var leases = scope.ServiceProvider.GetRequiredService<IBackgroundLeaseStore>();
                if (!await leases.TryAcquireAsync(LeaseName, LeaseOwner, LeaseTtl, stoppingToken)
                        .ConfigureAwait(false))
                {
                    Log.NotTheExporter(logger);
                    await DelayAsync(stoppingToken).ConfigureAwait(false);
                    continue;
                }

                var exporter = scope.ServiceProvider.GetRequiredService<AuditExportService>();
                var result = await exporter.ExportAsync(stoppingToken).ConfigureAwait(false);
                if (result.ExportedAnything)
                {
                    Log.Exported(logger, result.EventCount, result.FromSequence, result.ToSequence, result.ContentHash);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // An export failure leaves the chain unanchored for longer; it does not lose events,
                // and the next pass re-exports from the same point.
                Log.ExportFailed(logger, ex.Message);
            }

            if (!await DelayAsync(stoppingToken).ConfigureAwait(false))
            {
                break;
            }
        }
    }

    /// <summary>Waits for the next tick. False when shutdown interrupted it.</summary>
    private async Task<bool> DelayAsync(CancellationToken stoppingToken)
    {
        try
        {
            await Task.Delay(Interval, clock, stoppingToken).ConfigureAwait(false);
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
            Message = "audit_export_completed events={Count} range={From}..{To} sha256={ContentHash}")]
        public static partial void Exported(ILogger logger, int count, long from, long to, string contentHash);

        [LoggerMessage(Level = LogLevel.Warning,
            Message = "Audit export failed ({Reason}); the chain stays unanchored until the next attempt.")]
        public static partial void ExportFailed(ILogger logger, string reason);

        [LoggerMessage(Level = LogLevel.Debug,
            Message = "Another instance holds the audit-export lease; skipping this pass.")]
        public static partial void NotTheExporter(ILogger logger);
    }
}
