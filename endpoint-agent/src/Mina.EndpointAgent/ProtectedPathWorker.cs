using Microsoft.Extensions.Options;
using Mina.EndpointAgent.Configuration;
using Mina.EndpointAgent.Ipc;
using Mina.EndpointAgent.Proxy;
using Mina.EndpointAgent.Session;

namespace Mina.EndpointAgent;

/// <summary>
/// Runs the protected path: hold a research session, and keep the loopback proxy listening exactly
/// as long as that session is live. When the session goes away — revoked, lapsed, renewal refused,
/// control plane unreachable — the listener is torn down, so the research browser gets a connection
/// error instead of quietly reaching the internet through ordinary corporate egress (FR-007).
/// </summary>
/// <remarks>
/// The worker is also the only writer of protected-path state in <see cref="AgentRuntimeState"/>,
/// which is what the tray reports to the analyst (FR-006). Nothing the tray does changes that
/// state directly; it asks, this loop decides, and the panel reflects the outcome.
/// </remarks>
internal sealed partial class ProtectedPathWorker(
    ResearchSessionManager sessions,
    SessionTunnelConnectionFactory tunnelFactory,
    IPeerAuthorizer peerAuthorizer,
    AgentRuntimeState state,
    IOptions<MinaAgentOptions> options,
    ILoggerFactory loggerFactory,
    TimeProvider clock,
    ILogger<ProtectedPathWorker> logger) : BackgroundService
{
    private readonly MinaAgentOptions _options = options.Value;
    private LoopbackConnectProxy? _proxy;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                var wait = await TickAsync(stoppingToken).ConfigureAwait(false);

                // A tray command — reconnect, end, change region — wakes this early, so the panel
                // responds at once instead of at the next poll.
                await state.WaitForNextTickAsync(wait, clock, stoppingToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // normal shutdown
        }
        finally
        {
            await CloseProtectedPathAsync().ConfigureAwait(false);
            await sessions.EndAsync(CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>Runs one iteration and returns how long to wait before the next.</summary>
    private async Task<TimeSpan> TickAsync(CancellationToken cancellationToken)
    {
        if (state.Suspended)
        {
            // The analyst ended their session. Staying closed is the whole point — re-establishing
            // here would make "End session" mean "end it for thirty seconds".
            await CloseProtectedPathAsync().ConfigureAwait(false);
            return _options.PollInterval;
        }

        try
        {
            if (sessions.Current is null)
            {
                state.ReportConnecting();
                await sessions.EstablishAsync(state.Region, cancellationToken).ConfigureAwait(false);
                await OpenProtectedPathAsync().ConfigureAwait(false);
                state.ReportProtected(_proxy?.Endpoint?.Port ?? 0);
                return _options.PollInterval;
            }

            await sessions.RenewIfDueAsync(cancellationToken).ConfigureAwait(false);
            if (sessions.Current is null)
            {
                await CloseProtectedPathAsync().ConfigureAwait(false);
                return Fail("The session could not be renewed, so research browsing has stopped.");
            }

            state.ReportProtected(_proxy?.Endpoint?.Port ?? 0);
            return _options.PollInterval;
        }
        catch (Exception ex) when (ex is ControlPlaneException or HttpRequestException
                                   || (ex is OperationCanceledException && !cancellationToken.IsCancellationRequested))
        {
            // An HTTP timeout arrives as TaskCanceledException, which is an OperationCanceledException.
            // Letting it escape broke the worker's loop outright: the path closed, correctly, but
            // never reopened without a service restart. A timeout is transient — close the path and
            // try again on the next tick.
            Log.SessionUnavailable(logger, ex.Message);
            await CloseProtectedPathAsync().ConfigureAwait(false);
            return Fail(DescribeForAnalyst(ex));
        }
    }

    /// <summary>
    /// Records a failure and returns the backoff before the next attempt. The agent never stops
    /// retrying: a path that stays closed is the safe state, and the analyst can see why it is.
    /// </summary>
    private TimeSpan Fail(string reason)
    {
        var failuresSoFar = state.Snapshot().ConsecutiveFailures;
        var delay = BackoffFor(failuresSoFar);
        state.ReportFailed(reason, clock.GetUtcNow() + delay);
        return delay;
    }

    private TimeSpan BackoffFor(int failuresSoFar)
    {
        // Doubling, capped. Shifting past 30 would overflow, and the cap has long since applied.
        var doublings = Math.Min(failuresSoFar, 30);
        var scaled = _options.RetryInitialDelay * Math.Pow(2, doublings);
        return scaled >= _options.RetryMaxDelay ? _options.RetryMaxDelay : scaled;
    }

    /// <summary>
    /// Turns a failure into something the analyst can act on, without putting transport detail in
    /// front of them. The full message goes to the agent's log, not to the panel.
    /// </summary>
    private static string DescribeForAnalyst(Exception exception) => exception switch
    {
        ControlPlaneException { StatusCode: System.Net.HttpStatusCode.Forbidden } =>
            "The control plane declined to issue a session for this device, account or region.",
        ControlPlaneException { StatusCode: System.Net.HttpStatusCode.Unauthorized } =>
            "Your sign-in is no longer accepted. Sign in again to resume research browsing.",
        ControlPlaneException => "The control plane refused the session request.",
        _ => "The control plane cannot be reached from this device.",
    };

    private async Task OpenProtectedPathAsync()
    {
        await CloseProtectedPathAsync().ConfigureAwait(false);

        var proxy = new LoopbackConnectProxy(
            tunnelFactory, peerAuthorizer, loggerFactory.CreateLogger<LoopbackConnectProxy>());
        proxy.Start(_options.LoopbackPort);
        _proxy = proxy;

        Log.ProtectedPathOpen(logger, proxy.Endpoint?.Port ?? 0);
    }

    private async Task CloseProtectedPathAsync()
    {
        if (_proxy is null)
        {
            return;
        }

        await _proxy.DisposeAsync().ConfigureAwait(false);
        _proxy = null;
        Log.ProtectedPathClosed(logger);
    }

    private static partial class Log
    {
        [LoggerMessage(Level = LogLevel.Information,
            Message = "Protected path open; research browser proxy listening on 127.0.0.1:{Port}.")]
        public static partial void ProtectedPathOpen(ILogger logger, int port);

        [LoggerMessage(Level = LogLevel.Warning,
            Message = "Protected path closed; the research browser has no route out until a session is re-established.")]
        public static partial void ProtectedPathClosed(ILogger logger);

        [LoggerMessage(Level = LogLevel.Warning, Message = "Could not obtain or keep a research session: {Reason}")]
        public static partial void SessionUnavailable(ILogger logger, string reason);
    }
}
