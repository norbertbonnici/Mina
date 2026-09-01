using System.Collections.Concurrent;
using Microsoft.Extensions.Options;
using Mina.ControlPlane.Application.SensitiveSessions;
using Mina.ControlPlane.Application.Sessions;
using Mina.ControlPlane.Domain.SensitiveSessions;
using Mina.ControlPlane.Domain.Sessions;
using Mina.ControlPlane.Persistence;

namespace Mina.ControlPlane.Application.Tests;

public class SensitiveSessionServiceTests
{
    private static readonly DateTimeOffset T0 = new(2026, 8, 31, 9, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task Analyst_can_request_suppression_for_their_own_live_session()
    {
        var h = new Harness();

        var view = await h.Service.RequestAsync(h.Analyst, h.SessionId, "CASE-2026-0042", TimeSpan.FromHours(2), default);

        Assert.Equal(SensitiveSessionState.Requested, view.State);
        Assert.Equal(h.SessionId, view.SessionId);
        Assert.Equal("CASE-2026-0042", view.JustificationReference);
        Assert.Null(view.ApproverUpn);
    }

    [Fact]
    public async Task A_request_for_someone_elses_session_reports_not_found()
    {
        var h = new Harness();
        var other = h.Analyst with { UserObjectId = "oid-other", UserPrincipalName = "other@fiaumalta.org" };

        var ex = await Assert.ThrowsAsync<SensitiveSessionAuthorizationException>(
            () => h.Service.RequestAsync(other, h.SessionId, "CASE-1", TimeSpan.FromHours(1), default));

        // Not "forbidden": a stranger should not learn the session exists.
        Assert.Equal(SensitiveSessionDenialReason.SessionNotFound, ex.Reason);
    }

    [Fact]
    public async Task A_request_needs_a_live_session()
    {
        var h = new Harness();
        h.Session.End(T0.AddMinutes(1), SessionEndReason.EndedByUser);

        var ex = await Assert.ThrowsAsync<SensitiveSessionAuthorizationException>(
            () => h.Service.RequestAsync(h.Analyst, h.SessionId, "CASE-1", TimeSpan.FromHours(1), default));

        Assert.Equal(SensitiveSessionDenialReason.SessionNotUsable, ex.Reason);
    }

    [Fact]
    public async Task Approval_requires_the_approver_role()
    {
        var h = new Harness();
        var request = await h.RequestAsync();

        var ex = await Assert.ThrowsAsync<SensitiveSessionAuthorizationException>(
            () => h.Service.ApproveAsync(h.Analyst, request.RequestId, TimeSpan.FromHours(1), default));

        Assert.Equal(SensitiveSessionDenialReason.NotAuthorisedRole, ex.Reason);
    }

    [Fact]
    public async Task Holding_the_approver_role_still_does_not_permit_self_approval()
    {
        var h = new Harness();
        var request = await h.RequestAsync();

        // Same person, now also holding the approver role — the domain rule still refuses.
        var analystWhoIsAlsoApprover = h.Analyst with
        {
            Roles = new HashSet<string> { "Mina.Analyst", "Mina.Approver" },
        };

        var ex = await Assert.ThrowsAsync<SensitiveSessionRuleViolationException>(
            () => h.Service.ApproveAsync(analystWhoIsAlsoApprover, request.RequestId, TimeSpan.FromHours(1), default));

        Assert.Equal(SensitiveSessionRule.SelfApprovalForbidden, ex.Rule);
    }

    [Fact]
    public async Task Approval_records_the_approver_and_a_bounded_window()
    {
        var h = new Harness();
        var request = await h.RequestAsync();

        var approved = await h.Service.ApproveAsync(h.Approver, request.RequestId, TimeSpan.FromHours(1), default);

        Assert.Equal(SensitiveSessionState.Approved, approved.State);
        Assert.Equal("manager@fiaumalta.org", approved.ApproverUpn);
        Assert.Equal(T0.AddHours(1), approved.ExpiresAt);
    }

    [Fact]
    public async Task Approval_beyond_the_policy_maximum_is_rejected()
    {
        var h = new Harness();
        var request = await h.RequestAsync();

        var ex = await Assert.ThrowsAsync<SensitiveSessionRuleViolationException>(
            () => h.Service.ApproveAsync(h.Approver, request.RequestId, TimeSpan.FromHours(9), default));

        Assert.Equal(SensitiveSessionRule.TtlOutOfRange, ex.Rule);
    }

    [Fact]
    public async Task Suppression_cannot_activate_without_an_approval()
    {
        var h = new Harness();
        var request = await h.RequestAsync();

        // AC-010: the analyst holds the request but nobody has approved it.
        var ex = await Assert.ThrowsAsync<SensitiveSessionRuleViolationException>(
            () => h.Service.ActivateAsync(h.Analyst, request.RequestId, default));

        Assert.Equal(SensitiveSessionRule.InvalidTransition, ex.Rule);
        Assert.Equal(SessionMode.Normal, h.Session.Mode);
    }

    [Fact]
    public async Task Activation_after_approval_puts_the_session_into_sensitive_mode()
    {
        var h = new Harness();
        var request = await h.RequestAsync();
        await h.Service.ApproveAsync(h.Approver, request.RequestId, TimeSpan.FromHours(1), default);

        var activated = await h.Service.ActivateAsync(h.Analyst, request.RequestId, default);

        Assert.Equal(SensitiveSessionState.ActiveSuppressed, activated.State);
        Assert.Equal(SessionMode.Sensitive, h.Session.Mode);
    }

    [Fact]
    public async Task Activation_by_someone_other_than_the_requester_is_refused()
    {
        var h = new Harness();
        var request = await h.RequestAsync();
        await h.Service.ApproveAsync(h.Approver, request.RequestId, TimeSpan.FromHours(1), default);

        var ex = await Assert.ThrowsAsync<SensitiveSessionAuthorizationException>(
            () => h.Service.ActivateAsync(h.Approver, request.RequestId, default));

        Assert.Equal(SensitiveSessionDenialReason.NotRequester, ex.Reason);
    }

    [Fact]
    public async Task Denial_is_recorded_and_blocks_activation()
    {
        var h = new Harness();
        var request = await h.RequestAsync();

        var denied = await h.Service.DenyAsync(h.Approver, request.RequestId, default);
        Assert.Equal(SensitiveSessionState.Denied, denied.State);

        await Assert.ThrowsAsync<SensitiveSessionRuleViolationException>(
            () => h.Service.ActivateAsync(h.Analyst, request.RequestId, default));
        Assert.Equal(SessionMode.Normal, h.Session.Mode);
    }

    [Fact]
    public async Task Pending_queue_lists_only_undecided_requests_and_needs_the_approver_role()
    {
        var h = new Harness();
        var first = await h.RequestAsync("CASE-1");
        var second = await h.RequestAsync("CASE-2");
        await h.Service.DenyAsync(h.Approver, first.RequestId, default);

        var pending = await h.Service.ListPendingAsync(h.Approver, default);

        Assert.Equal([second.RequestId], pending.Select(p => p.RequestId));
        await Assert.ThrowsAsync<SensitiveSessionAuthorizationException>(
            () => h.Service.ListPendingAsync(h.Analyst, default));
    }

    [Fact]
    public async Task Expiry_ends_the_approval_and_terminates_the_session()
    {
        var h = new Harness();
        var request = await h.RequestAsync();
        await h.Service.ApproveAsync(h.Approver, request.RequestId, TimeSpan.FromHours(1), default);
        await h.Service.ActivateAsync(h.Analyst, request.RequestId, default);

        h.Clock.Advance(TimeSpan.FromHours(1));
        var expired = await h.Service.ExpireDueAsync(default);

        Assert.Equal(1, expired);
        var view = await h.Service.GetAsync(h.Analyst, request.RequestId, default);
        Assert.Equal(SensitiveSessionState.Ended, view.State);

        // D-06: the session goes with it rather than silently resuming URL logging.
        Assert.Equal(SessionState.Revoked, h.Session.State);
    }

    [Fact]
    public async Task Expiry_also_closes_an_approval_that_was_never_activated()
    {
        var h = new Harness();
        var request = await h.RequestAsync();
        await h.Service.ApproveAsync(h.Approver, request.RequestId, TimeSpan.FromMinutes(30), default);

        h.Clock.Advance(TimeSpan.FromMinutes(30));
        Assert.Equal(1, await h.Service.ExpireDueAsync(default));

        var view = await h.Service.GetAsync(h.Analyst, request.RequestId, default);
        Assert.Equal(SensitiveSessionState.Ended, view.State);
    }

    [Fact]
    public async Task Expiry_does_nothing_before_the_window_elapses()
    {
        var h = new Harness();
        var request = await h.RequestAsync();
        await h.Service.ApproveAsync(h.Approver, request.RequestId, TimeSpan.FromHours(1), default);

        h.Clock.Advance(TimeSpan.FromMinutes(59));

        Assert.Equal(0, await h.Service.ExpireDueAsync(default));
        Assert.Equal(SessionState.Active, h.Session.State);
    }

    [Fact]
    public async Task Requester_can_cancel_but_another_analyst_cannot()
    {
        var h = new Harness();
        var request = await h.RequestAsync();
        var other = h.Analyst with { UserObjectId = "oid-other" };

        await Assert.ThrowsAsync<SensitiveSessionRuleViolationException>(
            () => h.Service.CancelAsync(other, request.RequestId, default));

        var cancelled = await h.Service.CancelAsync(h.Analyst, request.RequestId, default);
        Assert.Equal(SensitiveSessionState.Cancelled, cancelled.State);
    }

    [Fact]
    public async Task An_unrelated_analyst_cannot_read_a_request()
    {
        var h = new Harness();
        var request = await h.RequestAsync();
        var other = h.Analyst with { UserObjectId = "oid-other" };

        var ex = await Assert.ThrowsAsync<SensitiveSessionAuthorizationException>(
            () => h.Service.GetAsync(other, request.RequestId, default));

        Assert.Equal(SensitiveSessionDenialReason.RequestNotFound, ex.Reason);
    }

    private sealed class Harness
    {
        public Harness()
        {
            Session = ResearchSession.Issue(
                SessionId, "oid-analyst", "analyst@fiaumalta.org", "device-1", "westeurope",
                T0, TimeSpan.FromHours(8), "SERIAL-1");
            Sessions.AddAsync(Session, default).GetAwaiter().GetResult();

            Service = new SensitiveSessionService(
                Requests, Sessions, NullSensitiveSessionAuditSink.Instance, new InMemoryUnitOfWork(),
                Options.Create(new SensitiveSessionOptions()), Clock);
        }

        public Guid SessionId { get; } = Guid.NewGuid();

        public ResearchSession Session { get; }

        public InMemorySessions Sessions { get; } = new();

        public InMemoryRequests Requests { get; } = new();

        public FakeClock Clock { get; } = new(T0);

        public SensitiveSessionService Service { get; }

        public SessionPrincipal Analyst =>
            new("oid-analyst", "analyst@fiaumalta.org", "device-1", new HashSet<string> { "Mina.Analyst" }, true);

        public SessionPrincipal Approver =>
            new("oid-manager", "manager@fiaumalta.org", "device-2", new HashSet<string> { "Mina.Approver" }, true);

        public Task<SensitiveSessionView> RequestAsync(string reference = "CASE-2026-0042") =>
            Service.RequestAsync(Analyst, SessionId, reference, TimeSpan.FromHours(2), default);
    }

    private sealed class FakeClock(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset _now = now;

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan by) => _now += by;
    }

    private sealed class InMemorySessions : ISessionRepository
    {
        private readonly ConcurrentDictionary<Guid, ResearchSession> _store = new();

        public Task AddAsync(ResearchSession session, CancellationToken cancellationToken)
        {
            _store[session.Id] = session;
            return Task.CompletedTask;
        }

        public Task<ResearchSession?> FindAsync(Guid id, CancellationToken cancellationToken) =>
            Task.FromResult(_store.GetValueOrDefault(id));

        public Task UpdateAsync(ResearchSession session, CancellationToken cancellationToken)
        {
            _store[session.Id] = session;
            return Task.CompletedTask;
        }
    }

    private sealed class InMemoryRequests : ISensitiveSessionRepository
    {
        private readonly ConcurrentDictionary<Guid, SensitiveSessionRequest> _store = new();

        public Task AddAsync(SensitiveSessionRequest request, CancellationToken cancellationToken)
        {
            _store[request.Id] = request;
            return Task.CompletedTask;
        }

        public Task<SensitiveSessionRequest?> FindAsync(Guid id, CancellationToken cancellationToken) =>
            Task.FromResult(_store.GetValueOrDefault(id));

        public Task UpdateAsync(SensitiveSessionRequest request, CancellationToken cancellationToken)
        {
            _store[request.Id] = request;
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<SensitiveSessionRequest>> ListPendingAsync(CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<SensitiveSessionRequest>>(
                [.. _store.Values.Where(r => r.State == SensitiveSessionState.Requested).OrderBy(r => r.RequestedAt)]);

        public Task<IReadOnlyList<SensitiveSessionRequest>> ListForSessionAsync(
            Guid sessionId, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<SensitiveSessionRequest>>(
                [.. _store.Values.Where(r => r.SessionId == sessionId)]);

        public Task<IReadOnlyList<SensitiveSessionRequest>> ListExpiredAsync(
            DateTimeOffset asOf, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<SensitiveSessionRequest>>(
                [.. _store.Values.Where(r =>
                    r.State is SensitiveSessionState.Approved or SensitiveSessionState.ActiveSuppressed
                    && r.ExpiresAt is not null && r.ExpiresAt <= asOf)]);
    }
}
