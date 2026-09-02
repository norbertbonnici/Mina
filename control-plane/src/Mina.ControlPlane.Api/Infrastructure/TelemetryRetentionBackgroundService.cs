using Microsoft.Extensions.Options;
using Mina.ControlPlane.Application.Telemetry;

namespace Mina.ControlPlane.Api.Infrastructure;

/// <summary>
/// Runs C3 retention on a timer (LOGGING_AND_PRIVACY §7, backlog M4-9).
/// </summary>
/// <remarks>
/// Not leased. Deleting expired rows is idempotent — a second instance running the same sweep finds
/// the rows already gone and removes nothing — so the coordination M4-23 added for the audit export
/// buys nothing here, and gating deletion on a lease would mean a retention commitment quietly
/// stops being met whenever the lease cannot be read.
/// </remarks>
internal sealed partial class TelemetryRetentionBackgroundService(
    IServiceScopeFactory scopeFactory,
    IOptions<TelemetryRetentionOptions> options,
    ILogger<TelemetryRetentionBackgroundService> logger,
    TimeProvider clock) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (options.Value.HostnameRetentionDays is not { } days)
        {
            // Said once, at Warning, and said plainly. An unenforced retention period reads as a
            // control in an assessment and is not one, so the platform states which it is rather
            // than leaving an operator to infer it from an absent setting.
            Log.RetentionDisabled(logger, TelemetryRetentionOptions.SectionName);
            return;
        }

        Log.RetentionEnabled(logger, days);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = scopeFactory.CreateScope();
                var retention = scope.ServiceProvider.GetRequiredService<TelemetryRetentionService>();
                var outcome = await retention.ApplyAsync(stoppingToken).ConfigureAwait(false);
                if (outcome.Total > 0)
                {
                    Log.RetentionApplied(logger, outcome.Hostnames, outcome.SuppressedSummaries);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // Failing to delete is a compliance problem, not an availability one. Taking the
                // host down with it would stop session issuance to fix a retention overrun, so the
                // failure is logged loudly and the next pass retries.
                Log.RetentionFailed(logger, ex.Message);
            }

            try
            {
                await Task.Delay(options.Value.Interval, clock, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    private static partial class Log
    {
        [LoggerMessage(EventId = 6100, Level = LogLevel.Warning,
            Message = "C3 telemetry retention is NOT enforced: {Section}:HostnameRetentionDays is unset, so hostname telemetry accumulates indefinitely.")]
        public static partial void RetentionDisabled(ILogger logger, string section);

        [LoggerMessage(EventId = 6101, Level = LogLevel.Information,
            Message = "C3 telemetry retention enforced at {Days} days.")]
        public static partial void RetentionEnabled(ILogger logger, int days);

        [LoggerMessage(EventId = 6102, Level = LogLevel.Information,
            Message = "C3 retention deleted {Hostnames} hostname observations and {Summaries} suppressed summaries.")]
        public static partial void RetentionApplied(ILogger logger, int hostnames, int summaries);

        [LoggerMessage(EventId = 6103, Level = LogLevel.Error,
            Message = "C3 retention pass failed: {Reason}")]
        public static partial void RetentionFailed(ILogger logger, string reason);
    }
}
