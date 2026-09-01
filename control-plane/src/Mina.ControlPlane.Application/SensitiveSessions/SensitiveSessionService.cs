using Microsoft.Extensions.Options;
using Mina.ControlPlane.Application.Sessions;
using Mina.ControlPlane.Domain;
using Mina.ControlPlane.Domain.SensitiveSessions;
using Mina.ControlPlane.Domain.Sessions;

namespace Mina.ControlPlane.Application.SensitiveSessions;

/// <summary>
/// A page of the approver queue. <paramref name="HasMore"/> exists so a flood cannot quietly push a
/// genuine request off the end of what an approver is shown.
/// </summary>
public sealed record PendingApprovals(IReadOnlyList<SensitiveSessionView> Requests, bool HasMore);

/// <summary>Policy for the sensitive-session workflow.</summary>
public sealed class SensitiveSessionOptions
{
    public const string Section = "Mina:SensitiveSession";

    /// <summary>App role required to decide a request. Deliberately not the analyst role.</summary>
    public string ApproverRole { get; set; } = "Mina.Approver";

    /// <summary>App role required to raise a request.</summary>
    public string AnalystRole { get; set; } = "Mina.Analyst";

    /// <summary>Longest suppression window an approver may grant.</summary>
    public TimeSpan MaxDuration { get; set; } = TimeSpan.FromHours(4);

    /// <summary>
    /// How many pending requests the approver queue returns at once. Provisional: it bounds a query
    /// an analyst can lengthen at will, and the value has not been ratified as policy. Truncation is
    /// always reported, so raising or lowering it changes how much an approver sees per page, never
    /// whether they are told there is more.
    /// </summary>
    public int ApproverQueuePageSize { get; set; } = 100;

    /// <summary>
    /// How many elapsed approvals one expiry sweep handles. The sweep repeats every 30 seconds and
    /// each expiry is independent, so a backlog drains over several passes instead of in one read.
    /// </summary>
    public int ExpirySweepBatchSize { get; set; } = 200;
}

/// <summary>
/// The manager-approved suppression workflow (ADR-0003, FR-009…FR-012). Every transition is
/// decided here, server-side: the analyst can ask, and can activate an approval someone else
/// granted, but cannot approve — and suppression exists only because this service says so, never
/// because a client asserted it.
/// </summary>
public sealed class SensitiveSessionService(
    ISensitiveSessionRepository requests,
    ISessionRepository sessions,
    ISensitiveSessionAuditSink audit,
    ISessionAuditSink sessionAudit,
    IUnitOfWork unitOfWork,
    IOptions<SensitiveSessionOptions> options,
    TimeProvider clock)
{
    private readonly ISensitiveSessionRepository _requests = requests ?? throw new ArgumentNullException(nameof(requests));
    private readonly ISessionRepository _sessions = sessions ?? throw new ArgumentNullException(nameof(sessions));
    private readonly ISensitiveSessionAuditSink _audit = audit ?? throw new ArgumentNullException(nameof(audit));
    private readonly ISessionAuditSink _sessionAudit =
        sessionAudit ?? throw new ArgumentNullException(nameof(sessionAudit));
    private readonly IUnitOfWork _unitOfWork = unitOfWork ?? throw new ArgumentNullException(nameof(unitOfWork));
    private readonly SensitiveSessionOptions _options =
        (options ?? throw new ArgumentNullException(nameof(options))).Value;

    private readonly TimeProvider _clock = clock ?? throw new ArgumentNullException(nameof(clock));

    private SensitiveSessionPolicy Policy => new(_options.MaxDuration);

    /// <summary>An analyst asks for suppression on their own live session.</summary>
    public async Task<SensitiveSessionView> RequestAsync(
        SessionPrincipal principal,
        Guid sessionId,
        string justificationReference,
        TimeSpan requestedDuration,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);
        RequireRole(principal, _options.AnalystRole);

        var session = await _sessions.FindAsync(sessionId, cancellationToken).ConfigureAwait(false)
            ?? throw new SensitiveSessionAuthorizationException(SensitiveSessionDenialReason.SessionNotFound);

        if (!string.Equals(session.UserObjectId, principal.UserObjectId, StringComparison.Ordinal))
        {
            // Not this analyst's session: report as not-found rather than confirming it exists.
            throw new SensitiveSessionAuthorizationException(SensitiveSessionDenialReason.SessionNotFound);
        }

        var now = _clock.GetUtcNow();
        if (!session.IsUsableAt(now))
        {
            throw new SensitiveSessionAuthorizationException(
                SensitiveSessionDenialReason.SessionNotUsable,
                "Suppression can only be requested for a live session.");
        }

        var request = SensitiveSessionRequest.Create(
            Guid.NewGuid(), sessionId, principal.UserObjectId, principal.UserPrincipalName,
            justificationReference, requestedDuration, Policy, now);

        // Audit before the record exists, so no approval trail can be missing its own beginning.
        await _audit.RequestedAsync(request, cancellationToken).ConfigureAwait(false);
        await _requests.AddAsync(request, cancellationToken).ConfigureAwait(false);
        return SensitiveSessionView.From(request);
    }

    /// <summary>An approver grants the request for a bounded window.</summary>
    public async Task<SensitiveSessionView> ApproveAsync(
        SessionPrincipal principal, Guid requestId, TimeSpan ttl, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);
        RequireRole(principal, _options.ApproverRole);

        var request = await RequireRequestAsync(requestId, cancellationToken).ConfigureAwait(false);

        // The domain enforces "not the requester"; holding the approver role is not enough.
        request.Approve(
            principal.UserObjectId, principal.UserPrincipalName, ttl, Policy, _clock.GetUtcNow());

        await _audit.ApprovedAsync(request, cancellationToken).ConfigureAwait(false);
        await _requests.UpdateAsync(request, cancellationToken).ConfigureAwait(false);
        return SensitiveSessionView.From(request);
    }

    public async Task<SensitiveSessionView> DenyAsync(
        SessionPrincipal principal, Guid requestId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);
        RequireRole(principal, _options.ApproverRole);

        var request = await RequireRequestAsync(requestId, cancellationToken).ConfigureAwait(false);
        request.Deny(principal.UserObjectId, principal.UserPrincipalName, _clock.GetUtcNow());

        await _audit.DeniedAsync(request, cancellationToken).ConfigureAwait(false);
        await _requests.UpdateAsync(request, cancellationToken).ConfigureAwait(false);
        return SensitiveSessionView.From(request);
    }

    /// <summary>The requester withdraws their own request before it is activated.</summary>
    public async Task<SensitiveSessionView> CancelAsync(
        SessionPrincipal principal, Guid requestId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);

        // Every other transition re-checks the role here rather than trusting the route. These two
        // did not, so the only role check on them came from the HTTP policy — which is built from
        // Mina:Session:AnalystRole while this workflow's own role is Mina:SensitiveSession:AnalystRole.
        // Two keys that are equal by default and need not stay equal.
        RequireRole(principal, _options.AnalystRole);

        var request = await RequireRequestAsync(requestId, cancellationToken).ConfigureAwait(false);

        // Ownership before state, matching ActivateAsync. The aggregate checks state first, so
        // asking it directly would answer a non-requester with a 409 for a decided request and a
        // 403 for an undecided one — the same oracle, one level down.
        if (!request.IsRequester(principal.UserObjectId))
        {
            await _audit.RequesterMismatchAsync(requestId, principal.UserObjectId, "cancel", cancellationToken)
                .ConfigureAwait(false);
            throw new SensitiveSessionAuthorizationException(SensitiveSessionDenialReason.NotRequester);
        }

        request.Cancel(principal.UserObjectId, _clock.GetUtcNow());

        await _audit.CancelledAsync(request, cancellationToken).ConfigureAwait(false);
        await _requests.UpdateAsync(request, cancellationToken).ConfigureAwait(false);
        return SensitiveSessionView.From(request);
    }

    /// <summary>
    /// Activates an approved request, putting the session into suppressed mode. The caller must be
    /// the requester, but the authority for the transition is the approval someone else recorded —
    /// an analyst can never reach this state on their own say-so (AC-010).
    /// </summary>
    public async Task<SensitiveSessionView> ActivateAsync(
        SessionPrincipal principal, Guid requestId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);
        RequireRole(principal, _options.AnalystRole);

        var request = await RequireRequestAsync(requestId, cancellationToken).ConfigureAwait(false);
        if (!request.IsRequester(principal.UserObjectId))
        {
            await _audit.RequesterMismatchAsync(requestId, principal.UserObjectId, "activate", cancellationToken)
                .ConfigureAwait(false);
            throw new SensitiveSessionAuthorizationException(SensitiveSessionDenialReason.NotRequester);
        }

        var now = _clock.GetUtcNow();
        var session = await _sessions.FindAsync(request.SessionId, cancellationToken).ConfigureAwait(false);
        if (session is null || !session.IsUsableAt(now))
        {
            throw new SensitiveSessionAuthorizationException(
                SensitiveSessionDenialReason.SessionNotUsable,
                "The session this approval belongs to is no longer live.");
        }

        request.Activate(now);
        session.MarkSensitive();

        await _audit.ActivatedAsync(request, cancellationToken).ConfigureAwait(false);

        // One commit: a half-applied activation would leave the request suppressed while the session
        // it names carried on in normal mode, or the reverse.
        await _unitOfWork.CommitAsync(cancellationToken).ConfigureAwait(false);
        return SensitiveSessionView.From(request);
    }

    /// <summary>The approver queue, bounded, and honest about being bounded.</summary>
    public async Task<PendingApprovals> ListPendingAsync(
        SessionPrincipal principal, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);
        RequireRole(principal, _options.ApproverRole);

        var page = await _requests
            .ListPendingAsync(_options.ApproverQueuePageSize, cancellationToken).ConfigureAwait(false);

        return new PendingApprovals([.. page.Requests.Select(SensitiveSessionView.From)], page.HasMore);
    }

    /// <summary>How many requests are waiting, for a dashboard that needs the number and not the rows.</summary>
    public async Task<int> CountPendingAsync(SessionPrincipal principal, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);
        RequireRole(principal, _options.ApproverRole);
        return await _requests.CountPendingAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>One request, visible to its requester or to an approver.</summary>
    public async Task<SensitiveSessionView> GetAsync(
        SessionPrincipal principal, Guid requestId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);

        var request = await RequireRequestAsync(requestId, cancellationToken).ConfigureAwait(false);
        if (!request.IsRequester(principal.UserObjectId) && !principal.Roles.Contains(_options.ApproverRole))
        {
            throw new SensitiveSessionAuthorizationException(SensitiveSessionDenialReason.RequestNotFound);
        }

        return SensitiveSessionView.From(request);
    }

    /// <summary>
    /// Ids of approvals whose window has elapsed. Split from <see cref="ExpireAsync"/> so the caller
    /// can expire each one in its own unit of work: a single unit of work cannot isolate failures,
    /// because a rejected commit leaves the failed change tracked and every later commit in that
    /// sweep re-attempts and re-fails it.
    /// </summary>
    public async Task<IReadOnlyList<Guid>> ListDueForExpiryAsync(CancellationToken cancellationToken)
    {
        var due = await _requests
            .ListExpiredAsync(_clock.GetUtcNow(), _options.ExpirySweepBatchSize, cancellationToken)
            .ConfigureAwait(false);
        return [.. due.Select(r => r.Id)];
    }

    /// <summary>
    /// Expires one approval and, per D-06, terminates the session it was granted for. Returns false
    /// when the request has already been decided by something else in the meantime — a race with an
    /// analyst ending it early is an ordinary outcome, not a failure.
    /// </summary>
    public async Task<bool> ExpireAsync(Guid requestId, CancellationToken cancellationToken)
    {
        var now = _clock.GetUtcNow();
        var request = await _requests.FindAsync(requestId, cancellationToken).ConfigureAwait(false);
        if (request is null || !request.TryExpire(now))
        {
            return false;
        }

        // D-06: expiry terminates the session rather than silently resuming URL logging on a
        // continuation of the same activity.
        // D-06, as amended 2026-09-01: expiry terminates the session only when suppression was
        // actually activated. An approval that was granted and never used suppressed nothing, so
        // there is no continuation of suppressed activity to protect — and taking a live, normally
        // logged session away because an unused approval lapsed taught analysts to avoid the
        // approved workflow, which is the opposite of what the workflow is for.
        // IsUsableAt, not State == Active: nothing sweeps lapsed session leases, so a session whose
        // lease ran out hours ago still sits at State = Active. Checking the state alone would
        // "terminate" a session that was already dead and write a session_revoked event asserting an
        // action that did nothing. A lapsed session needs no terminating — it is already unusable.
        var session = await _sessions.FindAsync(request.SessionId, cancellationToken).ConfigureAwait(false);
        var terminating = request.ActivatedAt is not null
            && session is not null && session.IsUsableAt(now);

        // Revoke BEFORE the audit write, not after. Both mutations are already tracked by the time
        // the audit event is appended, and appending flushes the whole unit of work — so writing the
        // event first committed the expiry (TryExpire, above) while leaving the revoke for a second
        // commit that could fail. That left an approval recorded as Ended with its session still
        // live and still suppressed, past the window an approver granted, and the due-request query
        // filters on Approved/ActiveSuppressed so no later sweep would ever pick it up again: a
        // permanent D-06 and AC-011 breach, with an audit event asserting a termination that never
        // happened. Ordering it this way makes the event and both state changes one transaction.
        if (terminating)
        {
            session!.Revoke(now, "sensitive-session-expiry");
        }

        await _audit.ExpiredAsync(request, terminating, cancellationToken).ConfigureAwait(false);

        if (terminating)
        {
            // The session's own terminal event as well. `sensitive_expired` records that a session
            // was terminated, but it is a Notice on the suppression workflow; `session_revoked` is
            // the High-severity event the session lifecycle defines and the one anything watching
            // session state is subscribed to. Without this, expiry was the only production path that
            // revokes a session and it emitted no session_revoked at all — leaving that event, and
            // its severity, unreachable in the whole system.
            await _sessionAudit.SessionEndedAsync(session!, cancellationToken).ConfigureAwait(false);
        }

        // Commits anything the audit append did not already flush; with the EF wiring this is a
        // no-op, and with a store that does not share the context it is the commit that counts.
        await _unitOfWork.CommitAsync(cancellationToken).ConfigureAwait(false);
        return true;
    }

    private async Task<SensitiveSessionRequest> RequireRequestAsync(Guid requestId, CancellationToken cancellationToken)
        => await _requests.FindAsync(requestId, cancellationToken).ConfigureAwait(false)
           ?? throw new SensitiveSessionAuthorizationException(SensitiveSessionDenialReason.RequestNotFound);

    private static void RequireRole(SessionPrincipal principal, string role)
    {
        if (!principal.Roles.Contains(role))
        {
            throw new SensitiveSessionAuthorizationException(SensitiveSessionDenialReason.NotAuthorisedRole);
        }
    }
}
