using Mina.ControlPlane.Application.Audit;

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

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = scopeFactory.CreateScope();
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
            catch (Exception ex) when (ex is IOException or InvalidOperationException or AuditWriteException)
            {
                // An export failure leaves the chain unanchored for longer; it does not lose events,
                // and the next pass re-exports from the same point.
                Log.ExportFailed(logger, ex.Message);
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
            Message = "audit_export_completed events={Count} range={From}..{To} sha256={ContentHash}")]
        public static partial void Exported(ILogger logger, int count, long from, long to, string contentHash);

        [LoggerMessage(Level = LogLevel.Warning,
            Message = "Audit export failed ({Reason}); the chain stays unanchored until the next attempt.")]
        public static partial void ExportFailed(ILogger logger, string reason);
    }
}
