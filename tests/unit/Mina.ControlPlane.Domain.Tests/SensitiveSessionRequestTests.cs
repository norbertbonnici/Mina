using Mina.ControlPlane.Domain.SensitiveSessions;

namespace Mina.ControlPlane.Domain.Tests;

public class SensitiveSessionRequestTests
{
    private static readonly SensitiveSessionPolicy Policy = new(TimeSpan.FromHours(4));
    private static readonly DateTimeOffset T0 = new(2026, 8, 31, 9, 0, 0, TimeSpan.Zero);
    private static readonly Guid SessionId = Guid.NewGuid();

    private const string AnalystOid = "oid-analyst";
    private const string AnalystUpn = "analyst@fiaumalta.org";
    private const string ApproverOid = "oid-manager";
    private const string ApproverUpn = "manager@fiaumalta.org";

    private static SensitiveSessionRequest NewRequest(TimeSpan? duration = null) =>
        SensitiveSessionRequest.Create(
            Guid.NewGuid(), SessionId, AnalystOid, AnalystUpn, "CASE-2026-0042",
            duration ?? TimeSpan.FromHours(2), Policy, T0);

    [Fact]
    public void Create_starts_in_requested_state_bound_to_a_session()
    {
        var request = NewRequest();

        Assert.Equal(SensitiveSessionState.Requested, request.State);
        Assert.Equal(SessionId, request.SessionId);
        Assert.Equal(AnalystOid, request.RequesterObjectId);
        Assert.Equal(AnalystUpn, request.RequesterUpn);
        Assert.Null(request.ExpiresAt);
        Assert.False(request.IsSuppressing);
    }

    [Fact]
    public void Create_requires_a_session()
    {
        var ex = Assert.Throws<SensitiveSessionRuleViolationException>(() =>
            SensitiveSessionRequest.Create(
                Guid.NewGuid(), Guid.Empty, AnalystOid, AnalystUpn, "CASE-1", TimeSpan.FromHours(1), Policy, T0));

        Assert.Equal(SensitiveSessionRule.SessionRequired, ex.Rule);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Create_requires_justification_reference(string justification)
    {
        var ex = Assert.Throws<SensitiveSessionRuleViolationException>(() =>
            SensitiveSessionRequest.Create(
                Guid.NewGuid(), SessionId, AnalystOid, AnalystUpn, justification,
                TimeSpan.FromHours(1), Policy, T0));

        Assert.Equal(SensitiveSessionRule.JustificationRequired, ex.Rule);
    }

    [Fact]
    public void Create_rejects_a_justification_reference_longer_than_the_column()
    {
        // A reference is a case number, not prose. Refusing it here rather than at the database
        // matters because the audit event is written before the action: a value that only fails on
        // insert leaves an approval request recorded that never existed.
        var ex = Assert.Throws<SensitiveSessionRuleViolationException>(() =>
            SensitiveSessionRequest.Create(
                Guid.NewGuid(), SessionId, AnalystOid, AnalystUpn,
                new string('x', SensitiveSessionRequest.MaxJustificationReferenceLength + 1),
                TimeSpan.FromHours(1), Policy, T0));

        Assert.Equal(SensitiveSessionRule.JustificationRequired, ex.Rule);

        // The boundary itself is accepted.
        var atLimit = SensitiveSessionRequest.Create(
            Guid.NewGuid(), SessionId, AnalystOid, AnalystUpn,
            new string('x', SensitiveSessionRequest.MaxJustificationReferenceLength),
            TimeSpan.FromHours(1), Policy, T0);
        Assert.Equal(
            SensitiveSessionRequest.MaxJustificationReferenceLength, atLimit.JustificationReference.Length);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-30)]
    [InlineData(300)] // above the 4h policy maximum
    public void Create_rejects_durations_outside_policy(int minutes)
    {
        var ex = Assert.Throws<SensitiveSessionRuleViolationException>(() =>
            NewRequest(TimeSpan.FromMinutes(minutes)));

        Assert.Equal(SensitiveSessionRule.DurationOutOfRange, ex.Rule);
    }

    [Fact]
    public void Approve_sets_approver_and_expiry_anchored_at_approval_time()
    {
        var request = NewRequest();
        var approvedAt = T0.AddMinutes(10);

        request.Approve(ApproverOid, ApproverUpn, TimeSpan.FromHours(1), Policy, approvedAt);

        Assert.Equal(SensitiveSessionState.Approved, request.State);
        Assert.Equal(ApproverOid, request.ApproverObjectId);
        Assert.Equal(ApproverUpn, request.ApproverUpn);
        Assert.Equal(approvedAt, request.ApprovedAt);
        Assert.Equal(approvedAt.AddHours(1), request.ExpiresAt);
    }

    [Fact]
    public void Approve_rejects_self_approval_on_object_id()
    {
        var request = NewRequest();

        // A different display name does not make the requester a different person.
        var ex = Assert.Throws<SensitiveSessionRuleViolationException>(() =>
            request.Approve(AnalystOid, "renamed.analyst@fiaumalta.org", TimeSpan.FromHours(1), Policy, T0));

        Assert.Equal(SensitiveSessionRule.SelfApprovalForbidden, ex.Rule);
        Assert.Equal(SensitiveSessionState.Requested, request.State);
    }

    [Fact]
    public void Approve_rejects_ttl_above_policy_maximum()
    {
        var request = NewRequest();

        var ex = Assert.Throws<SensitiveSessionRuleViolationException>(() =>
            request.Approve(ApproverOid, ApproverUpn, TimeSpan.FromHours(5), Policy, T0));

        Assert.Equal(SensitiveSessionRule.TtlOutOfRange, ex.Rule);
    }

    [Fact]
    public void Approve_twice_is_an_invalid_transition()
    {
        var request = NewRequest();
        request.Approve(ApproverOid, ApproverUpn, TimeSpan.FromHours(1), Policy, T0);

        var ex = Assert.Throws<SensitiveSessionRuleViolationException>(() =>
            request.Approve(ApproverOid, ApproverUpn, TimeSpan.FromHours(1), Policy, T0));

        Assert.Equal(SensitiveSessionRule.InvalidTransition, ex.Rule);
    }

    [Fact]
    public void Deny_rejects_decision_by_requester()
    {
        var request = NewRequest();

        var ex = Assert.Throws<SensitiveSessionRuleViolationException>(
            () => request.Deny(AnalystOid, AnalystUpn, T0));

        Assert.Equal(SensitiveSessionRule.SelfApprovalForbidden, ex.Rule);
    }

    [Fact]
    public void Deny_moves_to_denied()
    {
        var request = NewRequest();

        request.Deny(ApproverOid, ApproverUpn, T0.AddMinutes(5));

        Assert.Equal(SensitiveSessionState.Denied, request.State);
        Assert.Equal(ApproverOid, request.ApproverObjectId);
    }

    [Fact]
    public void Cancel_is_allowed_from_requested_and_approved_but_only_by_requester()
    {
        var requested = NewRequest();
        requested.Cancel(AnalystOid, T0.AddMinutes(1));
        Assert.Equal(SensitiveSessionState.Cancelled, requested.State);

        var approved = NewRequest();
        approved.Approve(ApproverOid, ApproverUpn, TimeSpan.FromHours(1), Policy, T0);
        approved.Cancel(AnalystOid, T0.AddMinutes(2));
        Assert.Equal(SensitiveSessionState.Cancelled, approved.State);

        var foreign = NewRequest();
        var ex = Assert.Throws<SensitiveSessionRuleViolationException>(() =>
            foreign.Cancel(ApproverOid, T0.AddMinutes(3)));
        Assert.Equal(SensitiveSessionRule.NotRequester, ex.Rule);
    }

    [Fact]
    public void Activate_requires_approval_first()
    {
        var request = NewRequest();

        var ex = Assert.Throws<SensitiveSessionRuleViolationException>(() => request.Activate(T0));

        Assert.Equal(SensitiveSessionRule.InvalidTransition, ex.Rule);
    }

    [Fact]
    public void Activate_inside_window_enters_active_suppressed()
    {
        var request = NewRequest();
        request.Approve(ApproverOid, ApproverUpn, TimeSpan.FromHours(1), Policy, T0);

        request.Activate(T0.AddMinutes(30));

        Assert.Equal(SensitiveSessionState.ActiveSuppressed, request.State);
        Assert.True(request.IsSuppressing);
        Assert.Equal(T0.AddMinutes(30), request.ActivatedAt);
        Assert.Equal(T0.AddHours(1), request.ExpiresAt); // late activation does not extend the window
    }

    [Fact]
    public void Activate_after_window_elapsed_is_rejected()
    {
        var request = NewRequest();
        request.Approve(ApproverOid, ApproverUpn, TimeSpan.FromHours(1), Policy, T0);

        var ex = Assert.Throws<SensitiveSessionRuleViolationException>(() =>
            request.Activate(T0.AddHours(2)));

        Assert.Equal(SensitiveSessionRule.ApprovalWindowElapsed, ex.Rule);
    }

    [Fact]
    public void TryExpire_before_expiry_does_nothing()
    {
        var request = NewRequest();
        request.Approve(ApproverOid, ApproverUpn, TimeSpan.FromHours(1), Policy, T0);
        request.Activate(T0.AddMinutes(1));

        Assert.False(request.TryExpire(T0.AddMinutes(59)));
        Assert.Equal(SensitiveSessionState.ActiveSuppressed, request.State);
    }

    [Fact]
    public void TryExpire_ends_active_suppression_at_ttl()
    {
        var request = NewRequest();
        request.Approve(ApproverOid, ApproverUpn, TimeSpan.FromHours(1), Policy, T0);
        request.Activate(T0.AddMinutes(1));

        Assert.True(request.TryExpire(T0.AddHours(1)));
        Assert.Equal(SensitiveSessionState.Ended, request.State);
        Assert.Equal(SensitiveSessionEndReason.Expired, request.EndReason);
        Assert.False(request.IsSuppressing);
    }

    [Fact]
    public void TryExpire_also_ends_approved_but_unused_requests()
    {
        var request = NewRequest();
        request.Approve(ApproverOid, ApproverUpn, TimeSpan.FromHours(1), Policy, T0);

        Assert.True(request.TryExpire(T0.AddHours(1)));
        Assert.Equal(SensitiveSessionState.Ended, request.State);
        Assert.Equal(SensitiveSessionEndReason.Expired, request.EndReason);
    }

    [Fact]
    public void EndEarly_only_valid_while_actively_suppressed()
    {
        var active = NewRequest();
        active.Approve(ApproverOid, ApproverUpn, TimeSpan.FromHours(1), Policy, T0);
        active.Activate(T0.AddMinutes(1));
        active.EndEarly(T0.AddMinutes(30));
        Assert.Equal(SensitiveSessionEndReason.EndedEarly, active.EndReason);

        var requested = NewRequest();
        var ex = Assert.Throws<SensitiveSessionRuleViolationException>(() => requested.EndEarly(T0));
        Assert.Equal(SensitiveSessionRule.InvalidTransition, ex.Rule);
    }
}
