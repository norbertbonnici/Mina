using System.Globalization;
using Microsoft.Extensions.Options;
using Mina.EndpointAgent.Configuration;
using Mina.EndpointAgent.Session;

namespace Mina.EndpointAgent.Ipc;

/// <summary>
/// Executes tray requests. This is the server side of ARCHITECTURE §3.1's rule that every
/// privileged operation is validated in the agent: the tray is a view and a set of buttons, and
/// nothing it sends is acted on before it has been checked here.
/// </summary>
/// <remarks>
/// Two things the tray deliberately cannot do. It cannot put a session into sensitive mode — it can
/// only ask the control plane, which requires an approver who is not the requester (AC-010). And it
/// cannot widen the region list: a region is accepted only if the control plane offered it, and the
/// control plane checks again when the session is issued (AC-008).
/// </remarks>
public sealed partial class TrayControlService(
    ISessionControl sessions,
    ControlPlaneClient controlPlane,
    AgentRuntimeState state,
    TrayFedAccessTokenProvider tokenSink,
    IOptions<MinaAgentOptions> options,
    TimeProvider clock,
    ILogger<TrayControlService> logger) : ITrayControl, IDisposable
{
    private readonly MinaAgentOptions _options =
        (options ?? throw new ArgumentNullException(nameof(options))).Value;

    private readonly SemaphoreSlim _mutex = new(1, 1);

    private DateTimeOffset _regionsRefreshedAt = DateTimeOffset.MinValue;
    private DateTimeOffset _sensitiveRefreshedAt = DateTimeOffset.MinValue;
    private int _disposed;

    /// <summary>
    /// Runs one request. <paramref name="clientIdentity"/> is the pipe peer's account, recorded so
    /// an operation on this endpoint can be attributed to a logon rather than to "the tray".
    /// </summary>
    /// <remarks>
    /// Tolerates <see cref="_mutex"/> already being disposed, both on entry and on release, for the
    /// same reason <c>ResearchSessionManager.EndAsync</c> does: <c>Program.cs</c> registers this
    /// type under two singleton slots (<c>TrayControlService</c> directly, and <c>ITrayControl</c>
    /// via a factory resolving the same instance), and the built-in <c>ServiceProvider</c> disposes
    /// each registration independently at host shutdown. A request already inside this method when
    /// either slot disposes would otherwise see an unhandled <see cref="ObjectDisposedException"/>.
    /// No live crash was observed here the way <c>ResearchSessionManager</c>'s was --
    /// <see cref="TrayIpcServer"/>'s own catch-all already turns an escaping exception here into an
    /// <c>agent_fault</c> response rather than letting it reach the host -- but a component that
    /// only survives because its one caller happens to wrap it defensively is still not safe on its
    /// own terms, so this closes the gap here too rather than leaving it as an implicit property of
    /// the caller.
    /// </remarks>
    public async Task<TrayResponse> ExecuteAsync(
        TrayRequest request, string? clientIdentity, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        try
        {
            await _mutex.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (ObjectDisposedException)
        {
            return Refused(
                TrayErrorCodes.AgentShuttingDown, "The agent is shutting down. Try again once it restarts.");
        }

        try
        {
            return request.Op switch
            {
                TrayOperations.Status => await StatusAsync(cancellationToken).ConfigureAwait(false),
                TrayOperations.SelectRegion =>
                    await SelectRegionAsync(request.Region, clientIdentity, cancellationToken).ConfigureAwait(false),
                TrayOperations.Reconnect =>
                    await ReconnectAsync(clientIdentity, cancellationToken).ConfigureAwait(false),
                TrayOperations.EndSession =>
                    await EndSessionAsync(clientIdentity, cancellationToken).ConfigureAwait(false),
                TrayOperations.RequestSensitive =>
                    await RequestSensitiveAsync(request, clientIdentity, cancellationToken).ConfigureAwait(false),
                TrayOperations.ActivateSensitive =>
                    await ActivateSensitiveAsync(clientIdentity, cancellationToken).ConfigureAwait(false),
                TrayOperations.CancelSensitive =>
                    await CancelSensitiveAsync(clientIdentity, cancellationToken).ConfigureAwait(false),
                TrayOperations.SubmitAccessToken => SubmitAccessToken(request, clientIdentity),
                _ => Refused(
                    TrayErrorCodes.UnknownOperation,
                    "This version of the agent does not support that action."),
            };
        }
        catch (ControlPlaneException ex)
        {
            Log.ControlPlaneRefused(logger, request.Op, ex.Message);
            return Refused(
                TrayErrorCodes.ControlPlaneRefused,
                "The control plane did not allow that. Try again, or contact the platform team if it persists.");
        }
        catch (NoAccessTokenAvailableException ex)
        {
            // Its own arm, not folded in with the transport failures below. ControlPlaneClient
            // throws this before sending anything, the moment it finds no token to attach, so
            // reporting it as an outage put two false statements in front of the analyst -- the
            // control plane is fine, and browsing is not waiting on it -- while hiding the one
            // thing they can actually act on. ProtectedPathWorker.DescribeForAnalyst already gives
            // this exception its own text for the same reason; this is the tray's side of that.
            Log.SignInRequired(logger, request.Op, ex.Message);
            return Refused(
                TrayErrorCodes.SignInRequired,
                "You are not signed in yet. The Mina tray signs in for you — complete any sign-in "
                + "prompt it shows, then try again.");
        }
        catch (Exception ex) when (ex is HttpRequestException
                                   || (ex is OperationCanceledException && !cancellationToken.IsCancellationRequested))
        {
            Log.ControlPlaneUnreachable(logger, request.Op, ex.Message);
            return Refused(
                TrayErrorCodes.ControlPlaneUnavailable,
                "The control plane cannot be reached. Research browsing stays closed until it can.");
        }
        finally
        {
            try
            {
                _mutex.Release();
            }
            catch (ObjectDisposedException)
            {
                // Disposed by the other DI registration slot while this request was still inside
                // the critical section (see the remarks above) -- nothing left to release.
            }
        }
    }

    private async Task<TrayResponse> StatusAsync(CancellationToken cancellationToken)
    {
        // Refreshes are best-effort and throttled: a status poll every second must not turn into a
        // control-plane call every second, and a control plane that is down must still yield a
        // status — that is precisely when the analyst is looking at the panel.
        await RefreshRegionsAsync(cancellationToken).ConfigureAwait(false);
        await RefreshSensitiveAsync(cancellationToken).ConfigureAwait(false);
        return TrayResponse.Success(BuildStatus());
    }

    private async Task<TrayResponse> SelectRegionAsync(
        string? region, string? clientIdentity, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(region))
        {
            return Refused(TrayErrorCodes.InvalidRequest, "No region was given.");
        }

        await RefreshRegionsAsync(cancellationToken).ConfigureAwait(false);

        var selectable = state.SelectableRegions;
        var match = selectable.FirstOrDefault(r => string.Equals(r, region, StringComparison.OrdinalIgnoreCase));
        if (match is null)
        {
            // Refusing on the agent's cached list is defence in depth, not the control. The control
            // plane refuses the issuance too, and its answer is the one that counts.
            Log.RegionRefused(logger, region, clientIdentity ?? "unknown");
            return Refused(
                TrayErrorCodes.RegionNotSelectable,
                selectable.Count == 0
                    ? "The list of available regions has not been retrieved yet. Try again in a moment."
                    : "That region is not available to you. Choose one from the list.");
        }

        if (string.Equals(match, state.Region, StringComparison.Ordinal) && sessions.Current is not null)
        {
            return TrayResponse.Success(BuildStatus());
        }

        // Changing region means a different egress identity, so the old session cannot carry over:
        // end it, then let the worker establish a new one.
        var wasSuspended = state.Suspended;
        state.SetRegion(match);
        await sessions.EndAsync(cancellationToken).ConfigureAwait(false);
        state.SetSensitiveRequest(null);

        if (!wasSuspended)
        {
            // An analyst who has ended their session and is picking where the next one goes has not
            // asked for a session — starting one here would take the decision away from them.
            state.Resume();
        }

        state.Wake();

        Log.RegionSelected(logger, match, clientIdentity ?? "unknown");
        return TrayResponse.Success(BuildStatus());
    }

    private async Task<TrayResponse> ReconnectAsync(string? clientIdentity, CancellationToken cancellationToken)
    {
        state.Resume();
        state.Wake();
        Log.ReconnectRequested(logger, clientIdentity ?? "unknown");

        await RefreshRegionsAsync(cancellationToken).ConfigureAwait(false);
        return TrayResponse.Success(BuildStatus());
    }

    private async Task<TrayResponse> EndSessionAsync(string? clientIdentity, CancellationToken cancellationToken)
    {
        try
        {
            await sessions.EndAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            // Suspend whatever happened above, rather than only on the happy path. EndAsync closes
            // the path locally before it tells the control plane, so by here the session is off this
            // endpoint either way — but nothing keeps it off: the worker re-establishes on its next
            // tick unless state.Suspended records that the analyst asked for it to stay closed. An
            // exception escaping this call therefore turned "End session" into "end it for a few
            // seconds", which is the one thing this operation must never mean. Which exception types
            // EndAsync swallows is its own business and must not decide that.
            state.Suspend();
            state.Wake();
        }

        Log.SessionEndedByAnalyst(logger, clientIdentity ?? "unknown");
        return TrayResponse.Success(BuildStatus());
    }

    private async Task<TrayResponse> RequestSensitiveAsync(
        TrayRequest request, string? clientIdentity, CancellationToken cancellationToken)
    {
        var session = sessions.Current;
        if (session is null)
        {
            return Refused(
                TrayErrorCodes.NoLiveSession,
                "A sensitive session can only be requested while you have a live research session.");
        }

        var reference = request.JustificationReference?.Trim();
        if (string.IsNullOrEmpty(reference))
        {
            return Refused(
                TrayErrorCodes.InvalidRequest, "Give the case or request reference this session is for.");
        }

        if (reference.Length > TrayProtocol.MaxJustificationReferenceLength)
        {
            return Refused(
                TrayErrorCodes.InvalidRequest,
                $"The reference must be {TrayProtocol.MaxJustificationReferenceLength} characters or fewer.");
        }

        if (reference.Any(char.IsControl))
        {
            // This string is written to the audit trail and read back by an approver. Control
            // characters have no business in a case reference and would let a local process shape
            // how that record renders.
            return Refused(TrayErrorCodes.InvalidRequest, "The reference contains characters that are not allowed.");
        }

        var minutes = request.Minutes ?? 0;
        if (minutes < 1 || minutes > _options.MaxSensitiveRequestMinutes)
        {
            var ceiling = _options.MaxSensitiveRequestMinutes.ToString(CultureInfo.InvariantCulture);
            return Refused(TrayErrorCodes.InvalidRequest, $"Ask for between 1 and {ceiling} minutes.");
        }

        var view = await controlPlane
            .RequestSensitiveAsync(session.SessionId, reference, minutes, cancellationToken).ConfigureAwait(false);

        state.SetSensitiveRequest(ToDto(view));
        _sensitiveRefreshedAt = clock.GetUtcNow();

        Log.SensitiveRequested(logger, view.RequestId, minutes, clientIdentity ?? "unknown");
        return TrayResponse.Success(BuildStatus());
    }

    private async Task<TrayResponse> ActivateSensitiveAsync(
        string? clientIdentity, CancellationToken cancellationToken)
    {
        var tracked = state.SensitiveRequest;
        if (tracked is null)
        {
            return Refused(TrayErrorCodes.NoSensitiveRequest, "There is no request to start.");
        }

        if (!string.Equals(tracked.State, "Approved", StringComparison.Ordinal))
        {
            // The control plane would refuse this anyway; refusing here keeps the tray from
            // presenting a start button as though approval were a formality.
            return Refused(TrayErrorCodes.NotApproved, "A manager has not approved this request yet.");
        }

        var view = await controlPlane
            .ActivateSensitiveAsync(tracked.RequestId, cancellationToken).ConfigureAwait(false);

        state.SetSensitiveRequest(ToDto(view));
        _sensitiveRefreshedAt = clock.GetUtcNow();

        Log.SensitiveActivated(logger, view.RequestId, clientIdentity ?? "unknown");
        return TrayResponse.Success(BuildStatus());
    }

    private async Task<TrayResponse> CancelSensitiveAsync(string? clientIdentity, CancellationToken cancellationToken)
    {
        var tracked = state.SensitiveRequest;
        if (tracked is null)
        {
            return Refused(TrayErrorCodes.NoSensitiveRequest, "There is no request to withdraw.");
        }

        var view = await controlPlane
            .CancelSensitiveAsync(tracked.RequestId, cancellationToken).ConfigureAwait(false);

        state.SetSensitiveRequest(ToDto(view));
        _sensitiveRefreshedAt = clock.GetUtcNow();

        Log.SensitiveCancelled(logger, view.RequestId, clientIdentity ?? "unknown");
        return TrayResponse.Success(BuildStatus());
    }

    /// <summary>
    /// Accepts a token the tray just acquired via the WAM broker (M2-4). Synchronous — this only
    /// updates in-process state, no control-plane call — but validated exactly like every other
    /// operation the tray can ask for: an empty or already-expired token is refused rather than
    /// silently stored, so a tray bug reads back as a refusal instead of a session that never
    /// establishes for a reason nothing reports.
    /// </summary>
    private TrayResponse SubmitAccessToken(TrayRequest request, string? clientIdentity)
    {
        if (string.IsNullOrWhiteSpace(request.AccessToken))
        {
            return Refused(TrayErrorCodes.InvalidRequest, "No access token was given.");
        }

        if (request.AccessTokenExpiresOn is not { } expiresOn || expiresOn <= clock.GetUtcNow())
        {
            return Refused(TrayErrorCodes.InvalidRequest, "The access token has no expiry, or has already expired.");
        }

        tokenSink.Submit(request.AccessToken, expiresOn);

        // A fresh token may be exactly what an EstablishAsync/RenewIfDueAsync waiting on
        // NoAccessTokenAvailableException needed — wake the worker rather than leaving it to the
        // next poll interval.
        state.Wake();

        Log.AccessTokenSubmitted(logger, expiresOn, clientIdentity ?? "unknown");
        return TrayResponse.Success(BuildStatus());
    }

    /// <summary>
    /// A refusal still carries the status: the analyst's next question after "no" is always "then
    /// what is happening", and a panel that blanks on error answers it badly.
    /// </summary>
    private TrayResponse Refused(string code, string message) =>
        TrayResponse.Failure(code, message, BuildStatus());

    private AgentStatusDto BuildStatus()
    {
        var snapshot = state.Snapshot();
        var session = sessions.Current;

        return new AgentStatusDto
        {
            State = snapshot.PathState,
            Region = session?.Region ?? snapshot.Region,
            Mode = ResolveMode(session, snapshot.Sensitive),
            SessionId = session?.SessionId,
            LeaseExpiresAt = session?.LeaseExpiresAt,
            ProxyPort = snapshot.ProxyPort,
            Reason = snapshot.Reason,
            ConsecutiveFailures = snapshot.ConsecutiveFailures,
            NextAttemptAt = snapshot.NextAttemptAt,
            SelectableRegions = snapshot.SelectableRegions,
            Sensitive = snapshot.Sensitive,
            MaxSensitiveMinutes = _options.MaxSensitiveRequestMinutes,
            ObservedAt = clock.GetUtcNow(),
            RequiredClaims = tokenSink.RequiredClaims,
        };
    }

    /// <summary>
    /// The session grant carries the mode the control plane stamped when it was issued, so it lags
    /// an activation until the next renewal. An activated request is the same authority saying the
    /// same thing more recently, so it wins — but both readings come from the control plane, never
    /// from the tray.
    /// </summary>
    private static string ResolveMode(IResearchSession? session, SensitiveRequestDto? sensitive) =>
        string.Equals(sensitive?.State, "ActiveSuppressed", StringComparison.Ordinal)
            ? "Sensitive"
            : session?.Mode ?? "Normal";

    private async Task RefreshRegionsAsync(CancellationToken cancellationToken)
    {
        var now = clock.GetUtcNow();
        if (state.SelectableRegions.Count > 0 && now - _regionsRefreshedAt < _options.RegionCacheLifetime)
        {
            return;
        }

        try
        {
            var regions = await controlPlane.GetSelectableRegionsAsync(cancellationToken).ConfigureAwait(false);
            state.SetSelectableRegions(regions);
            _regionsRefreshedAt = now;
        }
        catch (Exception ex) when (ex is ControlPlaneException or HttpRequestException or NoAccessTokenAvailableException
                                   || (ex is OperationCanceledException && !cancellationToken.IsCancellationRequested))
        {
            // Keep whatever list we already had. An empty list is refused at selection time with a
            // message that says to try again, which is better than a panel with no regions in it.
            // NoAccessTokenAvailableException included: before the tray has ever signed in, this is
            // the very first thing a status query hits, and Status must still answer (below).
            Log.RegionRefreshFailed(logger, ex.Message);
        }
    }

    private async Task RefreshSensitiveAsync(CancellationToken cancellationToken)
    {
        var tracked = state.SensitiveRequest;
        if (tracked is null || IsSettled(tracked.State))
        {
            return;
        }

        var now = clock.GetUtcNow();
        if (now - _sensitiveRefreshedAt < _options.SensitivePollInterval)
        {
            return;
        }

        try
        {
            var view = await controlPlane.GetSensitiveAsync(tracked.RequestId, cancellationToken).ConfigureAwait(false);
            state.SetSensitiveRequest(ToDto(view));
            _sensitiveRefreshedAt = now;
        }
        catch (Exception ex) when (ex is ControlPlaneException or HttpRequestException or NoAccessTokenAvailableException
                                   || (ex is OperationCanceledException && !cancellationToken.IsCancellationRequested))
        {
            Log.SensitiveRefreshFailed(logger, ex.Message);
        }
    }

    /// <summary>A request in one of these states will not change again on its own.</summary>
    private static bool IsSettled(string requestState) =>
        requestState is "Denied" or "Cancelled" or "Ended";

    private static SensitiveRequestDto ToDto(SensitiveRequestResponse view) => new()
    {
        RequestId = view.RequestId,
        State = view.State,
        JustificationReference = view.JustificationReference,
        RequestedMinutes = view.RequestedMinutes,
        ApproverUpn = view.ApproverUpn,
        ApprovedAt = view.ApprovedAt,
        ExpiresAt = view.ExpiresAt,
        ActivatedAt = view.ActivatedAt,
    };

    /// <summary>
    /// Idempotent, matching <c>ResearchSessionManager.DisposeAsync</c>'s guard for the same reason:
    /// <c>Program.cs</c>'s two singleton slots over this one instance (see <see cref="ExecuteAsync"/>'s
    /// remarks) both call <c>Dispose</c> at host shutdown. <see cref="SemaphoreSlim.Dispose()"/>
    /// itself already tolerates a second call -- it nulls its wait handle the first time and no-ops
    /// after, so this guard is not closing a crash inside disposal. What it protects is symmetry
    /// with <see cref="ExecuteAsync"/>'s own guard: the two are meant to be read together, and a
    /// disposal that were not idempotent while the request path defends against exactly that would
    /// be an easy inconsistency to reintroduce later without either half of it looking wrong on its
    /// own.
    /// </summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _mutex.Dispose();
    }

    private static partial class Log
    {
        [LoggerMessage(Level = LogLevel.Information, Message = "Analyst {Client} selected egress region {Region}.")]
        public static partial void RegionSelected(ILogger logger, string region, string client);

        [LoggerMessage(Level = LogLevel.Warning,
            Message = "Refused region {Region} requested by {Client}: not on the control plane's list.")]
        public static partial void RegionRefused(ILogger logger, string region, string client);

        [LoggerMessage(Level = LogLevel.Information, Message = "Analyst {Client} asked to reconnect.")]
        public static partial void ReconnectRequested(ILogger logger, string client);

        [LoggerMessage(Level = LogLevel.Information, Message = "Analyst {Client} ended the research session.")]
        public static partial void SessionEndedByAnalyst(ILogger logger, string client);

        [LoggerMessage(Level = LogLevel.Information,
            Message = "Sensitive session {RequestId} requested for {Minutes} minutes by {Client}.")]
        public static partial void SensitiveRequested(ILogger logger, Guid requestId, int minutes, string client);

        [LoggerMessage(Level = LogLevel.Information, Message = "Sensitive session {RequestId} activated by {Client}.")]
        public static partial void SensitiveActivated(ILogger logger, Guid requestId, string client);

        [LoggerMessage(Level = LogLevel.Information, Message = "Sensitive request {RequestId} withdrawn by {Client}.")]
        public static partial void SensitiveCancelled(ILogger logger, Guid requestId, string client);

        [LoggerMessage(Level = LogLevel.Information,
            Message = "Access token submitted by {Client}, expires {ExpiresOn:o}.")]
        public static partial void AccessTokenSubmitted(ILogger logger, DateTimeOffset expiresOn, string client);

        [LoggerMessage(Level = LogLevel.Warning, Message = "The control plane refused a tray {Operation}: {Reason}")]
        public static partial void ControlPlaneRefused(ILogger logger, string operation, string reason);

        [LoggerMessage(Level = LogLevel.Warning,
            Message = "The control plane was unreachable for tray {Operation}: {Reason}")]
        public static partial void ControlPlaneUnreachable(ILogger logger, string operation, string reason);

        [LoggerMessage(Level = LogLevel.Information,
            Message = "Tray {Operation} needs a sign-in that has not happened yet: {Reason}")]
        public static partial void SignInRequired(ILogger logger, string operation, string reason);

        [LoggerMessage(Level = LogLevel.Debug, Message = "Could not refresh the region list: {Reason}")]
        public static partial void RegionRefreshFailed(ILogger logger, string reason);

        [LoggerMessage(Level = LogLevel.Debug, Message = "Could not refresh the sensitive request: {Reason}")]
        public static partial void SensitiveRefreshFailed(ILogger logger, string reason);
    }
}
