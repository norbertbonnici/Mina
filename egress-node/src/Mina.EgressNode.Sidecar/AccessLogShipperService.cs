using Microsoft.Extensions.Options;

namespace Mina.EgressNode.Sidecar;

/// <summary>
/// Follows Envoy's access log and ships what it finds to the control plane, applying the node's
/// suppression view on the way out.
/// </summary>
internal sealed partial class AccessLogShipperService(
    ControlPlaneNodeClient client,
    TelemetryBatcher batcher,
    IOptions<SidecarOptions> options,
    TimeProvider clock,
    ILogger<AccessLogShipperService> logger) : BackgroundService
{
    private readonly SidecarOptions _options = options.Value;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var tail = TailAsync(stoppingToken);
        var ship = ShipLoopAsync(stoppingToken);
        await Task.WhenAll(tail, ship).ConfigureAwait(false);
    }

    /// <summary>Follows the log file, waiting for new lines and surviving rotation.</summary>
    private async Task TailAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            if (!File.Exists(_options.AccessLogPath))
            {
                await DelayAsync(TimeSpan.FromSeconds(2), cancellationToken).ConfigureAwait(false);
                continue;
            }

            try
            {
                await using var stream = new FileStream(
                    _options.AccessLogPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var reader = new StreamReader(stream);

                // Start at the end: the sidecar reports what happens from now on, and does not
                // re-ship a backlog whose sessions may since have become suppressed.
                stream.Seek(0, SeekOrigin.End);

                while (!cancellationToken.IsCancellationRequested)
                {
                    var line = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false);
                    if (line is null)
                    {
                        // Rotation: the file shrank, so reopen from the new beginning.
                        if (stream.Length < stream.Position)
                        {
                            break;
                        }

                        await DelayAsync(TimeSpan.FromMilliseconds(250), cancellationToken).ConfigureAwait(false);
                        continue;
                    }

                    if (AccessLogParser.TryParse(line) is { } entry)
                    {
                        batcher.Add(entry);
                    }
                }
            }
            catch (IOException ex)
            {
                Log.TailFailed(logger, ex.Message);
                await DelayAsync(TimeSpan.FromSeconds(2), cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private async Task ShipLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            await DelayAsync(_options.ShipInterval, cancellationToken).ConfigureAwait(false);
            if (cancellationToken.IsCancellationRequested)
            {
                break;
            }

            var batch = batcher.Drain();
            if (batch.Count == 0)
            {
                continue;
            }

            try
            {
                var accepted = await client.PostTelemetryAsync(_options.Region, batch, cancellationToken)
                    .ConfigureAwait(false);

                if (accepted.SuppressionMismatches > 0)
                {
                    // The control plane discarded destinations this node should not have sent: its
                    // allowlist is behind. Say so loudly here too — the discrepancy is the signal.
                    Log.SuppressionMismatch(logger, accepted.SuppressionMismatches);
                }
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException
                                       && !cancellationToken.IsCancellationRequested)
            {
                // The batch is dropped rather than retried indefinitely: telemetry is operational
                // data, and buffering it without bound on an egress node is its own risk. The gap
                // is visible as a delivery-lag alert upstream.
                Log.ShipFailed(logger, batch.Count, ex.Message);
            }
        }
    }

    private async Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken)
    {
        try
        {
            await Task.Delay(delay, clock, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // shutting down
        }
    }

    private static partial class Log
    {
        [LoggerMessage(Level = LogLevel.Warning, Message = "Reading the access log failed: {Reason}")]
        public static partial void TailFailed(ILogger logger, string reason);

        [LoggerMessage(Level = LogLevel.Warning,
            Message = "Could not ship {Count} telemetry item(s) ({Reason}); the batch was dropped.")]
        public static partial void ShipFailed(ILogger logger, int count, string reason);

        [LoggerMessage(Level = LogLevel.Error,
            Message = "The control plane discarded {Count} destination(s) for suppressed sessions — " +
                      "this node's allowlist is stale.")]
        public static partial void SuppressionMismatch(ILogger logger, int count);
    }
}
