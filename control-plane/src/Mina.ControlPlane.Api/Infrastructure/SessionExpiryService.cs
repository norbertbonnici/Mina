using Mina.ControlPlane.Application.Sessions;

namespace Mina.ControlPlane.Api.Infrastructure;

/// <summary>
/// Closes research sessions whose lease has elapsed, so a lapsed session becomes finished rather
/// than merely unusable.
/// </summary>
/// <remarks>
/// <see cref="ResearchSession.TryExpire"/> existed from M2-2 and had no production caller, which
/// had three consequences: `session_expired` was catalogued in EVENT_SCHEMAS and emitted by
/// nothing, so a session that simply ran out left a `session_started` with no matching end; the
/// active-session set grew without bound, and the egress nodes read it on every allowlist pull; and
/// anything reasoning about `State == Active` — including the D-06a check on whether an expiring
/// suppression should terminate its session — saw sessions that died hours ago.
///
/// Nothing here is a security boundary. The lease is already enforced on every request, and an
/// analyst cannot use a lapsed session whether or not this has run. This closes the record.
/// </remarks>
internal sealed partial class SessionExpiryService(
    IServiceScopeFactory scopeFactory,
    ILogger<SessionExpiryService> logger,
    TimeProvider clock) : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromMinutes(5);

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
                // A hosted service that throws stops the host by default, taking session issuance
                // with it. Nothing here is worth that: the lease is enforced on every request
                // regardless, so a failed sweep costs tidiness and the next pass retries.
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
    /// Closes every lapsed session, each in its own scope. The separate scopes are what make the
    /// per-session error handling meaningful: sharing one unit of work would leave a rejected
    /// change tracked, so the first failure would fail every later commit in the same sweep.
    /// </summary>
    internal static async Task<(int Expired, int Failed)> SweepAsync(
        IServiceScopeFactory scopeFactory, ILogger logger, CancellationToken cancellationToken)
    {
        IReadOnlyList<Guid> lapsed;
        using (var scope = scopeFactory.CreateScope())
        {
            lapsed = await scope.ServiceProvider.GetRequiredService<SessionService>()
                .ListLapsedForExpiryAsync(cancellationToken).ConfigureAwait(false);
        }

        var expired = 0;
        var failed = 0;
        foreach (var sessionId in lapsed)
        {
            try
            {
                using var scope = scopeFactory.CreateScope();
                var service = scope.ServiceProvider.GetRequiredService<SessionService>();
                if (await service.ExpireAsync(sessionId, cancellationToken).ConfigureAwait(false))
                {
                    expired++;
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                failed++;
                Log.SessionFailed(logger, sessionId, ex.Message);
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
        [LoggerMessage(Level = LogLevel.Information, Message = "Closed {Count} lapsed research session(s).")]
        public static partial void Expired(ILogger logger, int count);

        [LoggerMessage(Level = LogLevel.Warning, Message = "Session expiry sweep failed: {Reason}")]
        public static partial void SweepFailed(ILogger logger, string reason);

        [LoggerMessage(Level = LogLevel.Warning,
            Message = "session_expiry_failed session={SessionId} reason={Reason}; retrying next sweep.")]
        public static partial void SessionFailed(ILogger logger, Guid sessionId, string reason);
    }
}
