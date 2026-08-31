using Mina.ControlPlane.Domain.SensitiveSessions;

namespace Mina.ControlPlane.Domain.Tests;

public class SensitiveSessionRequestTests
{
    private static readonly SensitiveSessionPolicy Policy = new(TimeSpan.FromHours(4));
    private static readonly DateTimeOffset T0 = new(2026, 8, 31, 9, 0, 0, TimeSpan.Zero);

    private const string Analyst = "analyst@fiaumalta.org";
    private const string Approver = "manager@fiaumalta.org";

    private static SensitiveSessionRequest NewRequest(TimeSpan? duration = null) =>
        SensitiveSessionRequest.Create(
            Guid.NewGuid(), Analyst, "CASE-2026-0042", duration ?? TimeSpan.FromHours(2), Policy, T0);

    [Fact]
    public void Create_starts_in_requested_state()
    {
        var request = NewRequest();

        Assert.Equal(SensitiveSessionState.Requested, request.State);
        Assert.Equal(Analyst, request.RequesterUpn);
        Assert.Null(request.ExpiresAt);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Create_requires_justification_reference(string justification)
    {
        var ex = Assert.Throws<SensitiveSessionRuleViolationException>(() =>
            SensitiveSessionRequest.Create(Guid.NewGuid(), Analyst, justification, TimeSpan.FromHours(1), Policy, T0));

        Assert.Equal(SensitiveSessionRule.JustificationRequired, ex.Rule);
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

        request.Approve(Approver, TimeSpan.FromHours(1), Policy, approvedAt);

        Assert.Equal(SensitiveSessionState.Approved, request.State);
        Assert.Equal(Approver, request.ApproverUpn);
        Assert.Equal(approvedAt, request.ApprovedAt);
        Assert.Equal(approvedAt.AddHours(1), request.ExpiresAt);
    }

    [Theory]
    [InlineData(Analyst)]
    [InlineData("ANALYST@FIAUMALTA.ORG")] // identity comparison must be case-insensitive
    public void Approve_rejects_self_approval(string approver)
    {
        var request = NewRequest();

        var ex = Assert.Throws<SensitiveSessionRuleViolationException>(() =>
            request.Approve(approver, TimeSpan.FromHours(1), Policy, T0));

        Assert.Equal(SensitiveSessionRule.SelfApprovalForbidden, ex.Rule);
        Assert.Equal(SensitiveSessionState.Requested, request.State);
    }

    [Fact]
    public void Approve_rejects_ttl_above_policy_maximum()
    {
        var request = NewRequest();

        var ex = Assert.Throws<SensitiveSessionRuleViolationException>(() =>
            request.Approve(Approver, TimeSpan.FromHours(5), Policy, T0));

        Assert.Equal(SensitiveSessionRule.TtlOutOfRange, ex.Rule);
    }

    [Fact]
    public void Approve_twice_is_an_invalid_transition()
    {
        var request = NewRequest();
        request.Approve(Approver, TimeSpan.FromHours(1), Policy, T0);

        var ex = Assert.Throws<SensitiveSessionRuleViolationException>(() =>
            request.Approve(Approver, TimeSpan.FromHours(1), Policy, T0));

        Assert.Equal(SensitiveSessionRule.InvalidTransition, ex.Rule);
    }

    [Fact]
    public void Deny_rejects_decision_by_requester()
    {
        var request = NewRequest();

        var ex = Assert.Throws<SensitiveSessionRuleViolationException>(() => request.Deny(Analyst, T0));

        Assert.Equal(SensitiveSessionRule.SelfApprovalForbidden, ex.Rule);
    }

    [Fact]
    public void Deny_moves_to_denied()
    {
        var request = NewRequest();

        request.Deny(Approver, T0.AddMinutes(5));

        Assert.Equal(SensitiveSessionState.Denied, request.State);
        Assert.Equal(Approver, request.ApproverUpn);
    }

    [Fact]
    public void Cancel_is_allowed_from_requested_and_approved_but_only_by_requester()
    {
        var requested = NewRequest();
        requested.Cancel(Analyst, T0.AddMinutes(1));
        Assert.Equal(SensitiveSessionState.Cancelled, requested.State);

        var approved = NewRequest();
        approved.Approve(Approver, TimeSpan.FromHours(1), Policy, T0);
        approved.Cancel(Analyst, T0.AddMinutes(2));
        Assert.Equal(SensitiveSessionState.Cancelled, approved.State);

        var foreign = NewRequest();
        var ex = Assert.Throws<SensitiveSessionRuleViolationException>(() =>
            foreign.Cancel(Approver, T0.AddMinutes(3)));
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
        request.Approve(Approver, TimeSpan.FromHours(1), Policy, T0);

        request.Activate(T0.AddMinutes(30));

        Assert.Equal(SensitiveSessionState.ActiveSuppressed, request.State);
        Assert.Equal(T0.AddMinutes(30), request.ActivatedAt);
        Assert.Equal(T0.AddHours(1), request.ExpiresAt); // late activation does not extend the window
    }

    [Fact]
    public void Activate_after_window_elapsed_is_rejected()
    {
        var request = NewRequest();
        request.Approve(Approver, TimeSpan.FromHours(1), Policy, T0);

        var ex = Assert.Throws<SensitiveSessionRuleViolationException>(() =>
            request.Activate(T0.AddHours(2)));

        Assert.Equal(SensitiveSessionRule.ApprovalWindowElapsed, ex.Rule);
    }

    [Fact]
    public void TryExpire_before_expiry_does_nothing()
    {
        var request = NewRequest();
        request.Approve(Approver, TimeSpan.FromHours(1), Policy, T0);
        request.Activate(T0.AddMinutes(1));

        Assert.False(request.TryExpire(T0.AddMinutes(59)));
        Assert.Equal(SensitiveSessionState.ActiveSuppressed, request.State);
    }

    [Fact]
    public void TryExpire_ends_active_suppression_at_ttl()
    {
        var request = NewRequest();
        request.Approve(Approver, TimeSpan.FromHours(1), Policy, T0);
        request.Activate(T0.AddMinutes(1));

        Assert.True(request.TryExpire(T0.AddHours(1)));
        Assert.Equal(SensitiveSessionState.Ended, request.State);
        Assert.Equal(SensitiveSessionEndReason.Expired, request.EndReason);
    }

    [Fact]
    public void TryExpire_also_ends_approved_but_unused_requests()
    {
        var request = NewRequest();
        request.Approve(Approver, TimeSpan.FromHours(1), Policy, T0);

        Assert.True(request.TryExpire(T0.AddHours(1)));
        Assert.Equal(SensitiveSessionState.Ended, request.State);
        Assert.Equal(SensitiveSessionEndReason.Expired, request.EndReason);
    }

    [Fact]
    public void EndEarly_only_valid_while_actively_suppressed()
    {
        var active = NewRequest();
        active.Approve(Approver, TimeSpan.FromHours(1), Policy, T0);
        active.Activate(T0.AddMinutes(1));
        active.EndEarly(T0.AddMinutes(30));
        Assert.Equal(SensitiveSessionEndReason.EndedEarly, active.EndReason);

        var requested = NewRequest();
        var ex = Assert.Throws<SensitiveSessionRuleViolationException>(() => requested.EndEarly(T0));
        Assert.Equal(SensitiveSessionRule.InvalidTransition, ex.Rule);
    }
}
