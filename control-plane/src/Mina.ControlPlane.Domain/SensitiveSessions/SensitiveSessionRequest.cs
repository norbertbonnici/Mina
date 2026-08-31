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
/// extending it ("approval is time-bound", ADR-0003). Per the proposed D-06 default, expiry
/// terminates the research session; that behaviour lives in the control-plane service, while
/// this aggregate only reports the transition.
/// </remarks>
public sealed class SensitiveSessionRequest
{
    private static readonly StringComparer UpnComparer = StringComparer.OrdinalIgnoreCase;

    private SensitiveSessionRequest(
        Guid id,
        string requesterUpn,
        string justificationReference,
        TimeSpan requestedDuration,
        DateTimeOffset requestedAt)
    {
        Id = id;
        RequesterUpn = requesterUpn;
        JustificationReference = justificationReference;
        RequestedDuration = requestedDuration;
        RequestedAt = requestedAt;
        State = SensitiveSessionState.Requested;
    }

    public Guid Id { get; }

    public string RequesterUpn { get; }

    /// <summary>A case/justification reference — never justification content (threat N4).</summary>
    public string JustificationReference { get; }

    public TimeSpan RequestedDuration { get; }

    public DateTimeOffset RequestedAt { get; }

    public SensitiveSessionState State { get; private set; }

    public string? ApproverUpn { get; private set; }

    public DateTimeOffset? ApprovedAt { get; private set; }

    /// <summary>End of the approval window and of any suppression. Set on approval.</summary>
    public DateTimeOffset? ExpiresAt { get; private set; }

    public DateTimeOffset? ActivatedAt { get; private set; }

    public DateTimeOffset? EndedAt { get; private set; }

    public SensitiveSessionEndReason? EndReason { get; private set; }

    public static SensitiveSessionRequest Create(
        Guid id,
        string requesterUpn,
        string justificationReference,
        TimeSpan requestedDuration,
        SensitiveSessionPolicy policy,
        DateTimeOffset requestedAt)
    {
        ArgumentNullException.ThrowIfNull(policy);
        if (string.IsNullOrWhiteSpace(requesterUpn))
        {
            throw new SensitiveSessionRuleViolationException(
                SensitiveSessionRule.ActorRequired, "A requester identity is required.");
        }

        if (string.IsNullOrWhiteSpace(justificationReference))
        {
            throw new SensitiveSessionRuleViolationException(
                SensitiveSessionRule.JustificationRequired,
                "A justification reference is required to request a sensitive session.");
        }

        if (!policy.IsWithinLimit(requestedDuration))
        {
            throw new SensitiveSessionRuleViolationException(
                SensitiveSessionRule.DurationOutOfRange,
                $"Requested duration must be positive and at most {policy.MaxDuration}.");
        }

        return new SensitiveSessionRequest(id, requesterUpn, justificationReference, requestedDuration, requestedAt);
    }

    /// <summary>Approve with an explicit TTL. The approver must not be the requester (FR-010).</summary>
    public void Approve(string approverUpn, TimeSpan ttl, SensitiveSessionPolicy policy, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(policy);
        RequireActor(approverUpn);
        RequireState(SensitiveSessionState.Requested, nameof(Approve));
        if (UpnComparer.Equals(approverUpn, RequesterUpn))
        {
            throw new SensitiveSessionRuleViolationException(
                SensitiveSessionRule.SelfApprovalForbidden,
                "A sensitive session cannot be approved by its requester.");
        }

        if (!policy.IsWithinLimit(ttl))
        {
            throw new SensitiveSessionRuleViolationException(
                SensitiveSessionRule.TtlOutOfRange,
                $"Approval TTL must be positive and at most {policy.MaxDuration}.");
        }

        State = SensitiveSessionState.Approved;
        ApproverUpn = approverUpn;
        ApprovedAt = now;
        ExpiresAt = now + ttl;
    }

    /// <summary>Deny the request. Acting as approver on one's own request is equally forbidden.</summary>
    public void Deny(string approverUpn, DateTimeOffset now)
    {
        RequireActor(approverUpn);
        RequireState(SensitiveSessionState.Requested, nameof(Deny));
        if (UpnComparer.Equals(approverUpn, RequesterUpn))
        {
            throw new SensitiveSessionRuleViolationException(
                SensitiveSessionRule.SelfApprovalForbidden,
                "A sensitive session request cannot be decided by its requester.");
        }

        State = SensitiveSessionState.Denied;
        ApproverUpn = approverUpn;
        EndedAt = now;
    }

    /// <summary>The requester may withdraw before activation.</summary>
    public void Cancel(string byUpn, DateTimeOffset now)
    {
        RequireActor(byUpn);
        RequireState(nameof(Cancel), SensitiveSessionState.Requested, SensitiveSessionState.Approved);
        if (!UpnComparer.Equals(byUpn, RequesterUpn))
        {
            throw new SensitiveSessionRuleViolationException(
                SensitiveSessionRule.NotRequester, "Only the requester may cancel their request.");
        }

        State = SensitiveSessionState.Cancelled;
        EndedAt = now;
    }

    /// <summary>
    /// Activation is performed by the control plane only, never directly by the analyst
    /// (ARCHITECTURE §7), and only inside the approval window.
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

    private static void RequireActor(string upn)
    {
        if (string.IsNullOrWhiteSpace(upn))
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
