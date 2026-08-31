using Microsoft.Extensions.Options;
using Mina.ControlPlane.Application.Sessions;
using Mina.ControlPlane.Domain.SensitiveSessions;
using Mina.ControlPlane.Domain.Sessions;

namespace Mina.ControlPlane.Application.SensitiveSessions;

/// <summary>Policy for the sensitive-session workflow.</summary>
public sealed class SensitiveSessionOptions
{
    /// <summary>App role required to decide a request. Deliberately not the analyst role.</summary>
    public string ApproverRole { get; set; } = "Mina.Approver";

    /// <summary>App role required to raise a request.</summary>
    public string AnalystRole { get; set; } = "Mina.Analyst";

    /// <summary>Longest suppression window an approver may grant.</summary>
    public TimeSpan MaxDuration { get; set; } = TimeSpan.FromHours(4);
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
    IOptions<SensitiveSessionOptions> options,
    TimeProvider clock)
{
    private readonly ISensitiveSessionRepository _requests = requests ?? throw new ArgumentNullException(nameof(requests));
    private readonly ISessionRepository _sessions = sessions ?? throw new ArgumentNullException(nameof(sessions));
    private readonly ISensitiveSessionAuditSink _audit = audit ?? throw new ArgumentNullException(nameof(audit));
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

        var request = await RequireRequestAsync(requestId, cancellationToken).ConfigureAwait(false);
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

        var request = await RequireRequestAsync(requestId, cancellationToken).ConfigureAwait(false);
        if (!request.IsRequester(principal.UserObjectId))
        {
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
        await _requests.UpdateAsync(request, cancellationToken).ConfigureAwait(false);
        await _sessions.UpdateAsync(session, cancellationToken).ConfigureAwait(false);
        return SensitiveSessionView.From(request);
    }

    /// <summary>The approver queue.</summary>
    public async Task<IReadOnlyList<SensitiveSessionView>> ListPendingAsync(
        SessionPrincipal principal, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);
        RequireRole(principal, _options.ApproverRole);

        var pending = await _requests.ListPendingAsync(cancellationToken).ConfigureAwait(false);
        return [.. pending.Select(SensitiveSessionView.From)];
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
    /// Expires every approval whose window has elapsed and terminates the session it belonged to
    /// (D-06). Runs on a timer so an approval cannot outlive its TTL even if nothing else happens;
    /// returns how many were expired.
    /// </summary>
    public async Task<int> ExpireDueAsync(CancellationToken cancellationToken)
    {
        var now = _clock.GetUtcNow();
        var due = await _requests.ListExpiredAsync(now, cancellationToken).ConfigureAwait(false);

        var expired = 0;
        foreach (var request in due)
        {
            if (!request.TryExpire(now))
            {
                continue;
            }

            // D-06: expiry terminates the session rather than silently resuming URL logging on a
            // continuation of the same activity. Whether it will be terminated is decided before the
            // event is written, so the event is accurate and still precedes the change it describes.
            var session = await _sessions.FindAsync(request.SessionId, cancellationToken).ConfigureAwait(false);
            var terminating = session is not null && session.State == SessionState.Active;

            await _audit.ExpiredAsync(request, terminating, cancellationToken).ConfigureAwait(false);
            await _requests.UpdateAsync(request, cancellationToken).ConfigureAwait(false);

            if (terminating)
            {
                session!.Revoke(now, "sensitive-session-expiry");
                await _sessions.UpdateAsync(session, cancellationToken).ConfigureAwait(false);
            }

            expired++;
        }

        return expired;
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
