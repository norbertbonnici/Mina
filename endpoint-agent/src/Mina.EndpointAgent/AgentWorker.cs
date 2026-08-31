namespace Mina.EndpointAgent;

/// <summary>
/// Placeholder host loop. The real subsystems arrive with their milestones:
/// session manager + loopback proxy + tunnel client (M1-4), WFP enforcement, IPC and tamper
/// telemetry (M2-4). Until then the worker only reports that it is a skeleton, so a deployed
/// build can never be mistaken for a protecting one.
/// </summary>
internal sealed partial class AgentWorker(ILogger<AgentWorker> logger) : BackgroundService
{
    [LoggerMessage(Level = LogLevel.Warning,
        Message = "Mina endpoint agent skeleton (M0): no protection is active in this build.")]
    private static partial void LogSkeletonWarning(ILogger logger);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        LogSkeletonWarning(logger);
        try
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, stoppingToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // normal shutdown
        }
    }
}
