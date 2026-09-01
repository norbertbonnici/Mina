namespace Mina.ControlPlane.Domain.SensitiveSessions;

/// <summary>
/// The sensitive-session request aggregate: the authoritative state machine of ADR-0003.
/// Time is always passed in by the caller so behaviour is deterministic and testable; the
/// control plane supplies its clock, never the analyst endpoint.
/// </summary>
/// <remarks>
/// The approval TTL anchors at the moment of approval: <see cref="ExpiresAt"/> =
/// approval time + TTL. Activation must happen inside that window and suppression always ends
/// at <see cref="ExpiresAt"/> — a late activation shrinks the suppressed window rather than
/// extending it ("approval is time-bound", ADR-0003). Per D-06, expiry terminates the research
/// session; that consequence lives in the control-plane service, while this aggregate only
/// reports the transition.
///
/// Identity is compared on the Entra object id, not the UPN: object ids are immutable, whereas a
/// renamed UPN would silently weaken the no-self-approval rule.
/// </remarks>
public sealed class SensitiveSessionRequest
{
    /// <summary>
    /// Longest justification reference accepted. Matches the storage column, and is enforced here so
    /// an over-long value is refused as bad input rather than failing at the database — where, since
    /// audit precedes the action, it would leave an audit event for a request that never existed.
    /// </summary>
    public const int MaxJustificationReferenceLength = 128;

    private SensitiveSessionRequest(
        Guid id,
        Guid sessionId,
        string requesterObjectId,
        string requesterUpn,
        string justificationReference,
        TimeSpan requestedDuration,
        DateTimeOffset requestedAt)
    {
        Id = id;
        SessionId = sessionId;
        RequesterObjectId = requesterObjectId;
        RequesterUpn = requesterUpn;
        JustificationReference = justificationReference;
        RequestedDuration = requestedDuration;
        RequestedAt = requestedAt;
        State = SensitiveSessionState.Requested;
    }

    public Guid Id { get; }

    /// <summary>The research session this suppression applies to.</summary>
    public Guid SessionId { get; }

    public string RequesterObjectId { get; }

    public string RequesterUpn { get; }

    /// <summary>A case/justification reference — never justification content (threat N4).</summary>
    public string JustificationReference { get; }

    public TimeSpan RequestedDuration { get; }

    public DateTimeOffset RequestedAt { get; }

    public SensitiveSessionState State { get; private set; }

    public string? ApproverObjectId { get; private set; }

    public string? ApproverUpn { get; private set; }

    public DateTimeOffset? ApprovedAt { get; private set; }

    /// <summary>End of the approval window and of any suppression. Set on approval.</summary>
    public DateTimeOffset? ExpiresAt { get; private set; }

    public DateTimeOffset? ActivatedAt { get; private set; }

    public DateTimeOffset? EndedAt { get; private set; }

    public SensitiveSessionEndReason? EndReason { get; private set; }

    public static SensitiveSessionRequest Create(
        Guid id,
        Guid sessionId,
        string requesterObjectId,
        string requesterUpn,
        string justificationReference,
        TimeSpan requestedDuration,
        SensitiveSessionPolicy policy,
        DateTimeOffset requestedAt)
    {
        ArgumentNullException.ThrowIfNull(policy);
        if (sessionId == Guid.Empty)
        {
            throw new SensitiveSessionRuleViolationException(
                SensitiveSessionRule.SessionRequired, "A session id is required.");
        }

        if (string.IsNullOrWhiteSpace(requesterObjectId) || string.IsNullOrWhiteSpace(requesterUpn))
        {
            throw new SensitiveSessionRuleViolationException(
                SensitiveSessionRule.ActorRequired, "A requester identity is required.");
        }

        if (string.IsNullOrWhiteSpace(justificationReference)
            || justificationReference.Length > MaxJustificationReferenceLength)
        {
            throw new SensitiveSessionRuleViolationException(
                SensitiveSessionRule.JustificationRequired,
                "A justification reference is required, of at most "
                + $"{MaxJustificationReferenceLength} characters.");
        }

        if (!policy.IsWithinLimit(requestedDuration))
        {
            throw new SensitiveSessionRuleViolationException(
                SensitiveSessionRule.DurationOutOfRange,
                $"Requested duration must be positive and at most {policy.MaxDuration}.");
        }

        return new SensitiveSessionRequest(
            id, sessionId, requesterObjectId, requesterUpn, justificationReference, requestedDuration, requestedAt);
    }

    /// <summary>Approve with an explicit TTL. The approver must not be the requester (FR-010).</summary>
    public void Approve(
        string approverObjectId, string approverUpn, TimeSpan ttl, SensitiveSessionPolicy policy, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(policy);
        RequireActor(approverObjectId, approverUpn);
        RequireState(SensitiveSessionState.Requested, nameof(Approve));
        RequireNotRequester(approverObjectId, "A sensitive session cannot be approved by its requester.");

        if (!policy.IsWithinLimit(ttl))
        {
            throw new SensitiveSessionRuleViolationException(
                SensitiveSessionRule.TtlOutOfRange,
                $"Approval TTL must be positive and at most {policy.MaxDuration}.");
        }

        State = SensitiveSessionState.Approved;
        ApproverObjectId = approverObjectId;
        ApproverUpn = approverUpn;
        ApprovedAt = now;
        ExpiresAt = now + ttl;
    }

    /// <summary>Deny the request. Acting as approver on one's own request is equally forbidden.</summary>
    public void Deny(string approverObjectId, string approverUpn, DateTimeOffset now)
    {
        RequireActor(approverObjectId, approverUpn);
        RequireState(SensitiveSessionState.Requested, nameof(Deny));
        RequireNotRequester(approverObjectId, "A sensitive session request cannot be decided by its requester.");

        State = SensitiveSessionState.Denied;
        ApproverObjectId = approverObjectId;
        ApproverUpn = approverUpn;
        EndedAt = now;
    }

    /// <summary>The requester may withdraw before activation.</summary>
    public void Cancel(string byObjectId, DateTimeOffset now)
    {
        RequireActor(byObjectId, "n/a");
        RequireState(nameof(Cancel), SensitiveSessionState.Requested, SensitiveSessionState.Approved);
        if (!IsRequester(byObjectId))
        {
            throw new SensitiveSessionRuleViolationException(
                SensitiveSessionRule.NotRequester, "Only the requester may cancel their request.");
        }

        State = SensitiveSessionState.Cancelled;
        EndedAt = now;
    }

    /// <summary>
    /// Activation is performed by the control plane only, never directly by the analyst
    /// (ARCHITECTURE §7), and only inside the approval window. The authority for the transition is
    /// the existing approval by someone else, not the caller.
    /// </summary>
    public void Activate(DateTimeOffset now)
    {
        RequireState(SensitiveSessionState.Approved, nameof(Activate));
        if (now >= ExpiresAt)
        {
            throw new SensitiveSessionRuleViolationException(
                SensitiveSessionRule.ApprovalWindowElapsed,
                "The approval window has elapsed; a new request is required.");
        }

        State = SensitiveSessionState.ActiveSuppressed;
        ActivatedAt = now;
    }

    /// <summary>
    /// Transitions to Ended(Expired) once the TTL has elapsed; returns whether a transition
    /// occurred. Applies to both approved-but-unused and actively suppressed requests, so no
    /// approval can outlive its window (AC-011).
    /// </summary>
    public bool TryExpire(DateTimeOffset now)
    {
        var expirable = State is SensitiveSessionState.Approved or SensitiveSessionState.ActiveSuppressed;
        if (!expirable || now < ExpiresAt)
        {
            return false;
        }

        State = SensitiveSessionState.Ended;
        EndReason = SensitiveSessionEndReason.Expired;
        EndedAt = now;
        return true;
    }

    /// <summary>Analyst (or control plane) ends the suppressed session before expiry.</summary>
    public void EndEarly(DateTimeOffset now)
    {
        RequireState(SensitiveSessionState.ActiveSuppressed, nameof(EndEarly));
        State = SensitiveSessionState.Ended;
        EndReason = SensitiveSessionEndReason.EndedEarly;
        EndedAt = now;
    }

    /// <summary>True while this request is authoritatively suppressing URL telemetry.</summary>
    public bool IsSuppressing => State == SensitiveSessionState.ActiveSuppressed;

    public bool IsRequester(string objectId) =>
        string.Equals(RequesterObjectId, objectId, StringComparison.Ordinal);

    private void RequireNotRequester(string approverObjectId, string message)
    {
        if (IsRequester(approverObjectId))
        {
            throw new SensitiveSessionRuleViolationException(
                SensitiveSessionRule.SelfApprovalForbidden, message);
        }
    }

    private static void RequireActor(string objectId, string upn)
    {
        if (string.IsNullOrWhiteSpace(objectId) || string.IsNullOrWhiteSpace(upn))
        {
            throw new SensitiveSessionRuleViolationException(
                SensitiveSessionRule.ActorRequired, "An acting identity is required.");
        }
    }

    private void RequireState(SensitiveSessionState expected, string operation)
        => RequireState(operation, expected);

    private void RequireState(string operation, params SensitiveSessionState[] expected)
    {
        if (!expected.Contains(State))
        {
            throw new SensitiveSessionRuleViolationException(
                SensitiveSessionRule.InvalidTransition,
                $"{operation} is not valid from state {State}.");
        }
    }
}
