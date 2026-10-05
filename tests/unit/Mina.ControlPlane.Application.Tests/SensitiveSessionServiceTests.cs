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
        var other = h.Analyst with { UserObjectId = "oid-other", UserPrincipalName = "other@example.org" };

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
        Assert.Equal("manager@example.org", approved.ApproverUpn);
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

        // Another analyst: holds the role, so this isolates the requester check rather than
        // tripping on the role first. Activation's authority is the approval someone else granted,
        // and it belongs to the analyst who asked — nobody else can spend it.
        var otherAnalyst = h.Analyst with { UserObjectId = "oid-other-analyst" };

        var ex = await Assert.ThrowsAsync<SensitiveSessionAuthorizationException>(
            () => h.Service.ActivateAsync(otherAnalyst, request.RequestId, default));

        Assert.Equal(SensitiveSessionDenialReason.NotRequester, ex.Reason);

        // And the approver, who granted it, cannot activate it either — they lack the analyst role.
        var approver = await Assert.ThrowsAsync<SensitiveSessionAuthorizationException>(
            () => h.Service.ActivateAsync(h.Approver, request.RequestId, default));
        Assert.Equal(SensitiveSessionDenialReason.NotAuthorisedRole, approver.Reason);
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
        // A second session: one session may only carry one undecided request.
        var second = await h.RequestOnNewSessionAsync("CASE-2");
        await h.Service.DenyAsync(h.Approver, first.RequestId, default);

        var pending = await h.Service.ListPendingAsync(h.Approver, default);

        Assert.Equal([second.RequestId], pending.Requests.Select(p => p.RequestId));
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
        var expired = await h.ExpireDueAsync();

        Assert.Equal(1, expired);
        var view = await h.Service.GetAsync(h.Analyst, request.RequestId, default);
        Assert.Equal(SensitiveSessionState.Ended, view.State);

        // D-06: the session goes with it rather than silently resuming URL logging.
        Assert.Equal(SessionState.Revoked, h.Session.State);
    }

    [Fact]
    public async Task Expiry_closes_an_unused_approval_without_taking_the_analysts_session()
    {
        var h = new Harness();
        var request = await h.RequestAsync();
        await h.Service.ApproveAsync(h.Approver, request.RequestId, TimeSpan.FromMinutes(30), default);

        h.Clock.Advance(TimeSpan.FromMinutes(30));
        Assert.Equal(1, await h.ExpireDueAsync());

        // The approval lapses, so nothing can be activated on it afterwards (AC-011)...
        var view = await h.Service.GetAsync(h.Analyst, request.RequestId, default);
        Assert.Equal(SensitiveSessionState.Ended, view.State);

        // ...but D-06a: it was never activated, so it suppressed nothing and there is no
        // suppressed activity to stop. Ending the analyst's normally logged session here punished
        // them for using the approved workflow.
        Assert.Equal(SessionState.Active, h.Session.State);
        Assert.Equal(SessionMode.Normal, h.Session.Mode);
    }

    [Fact]
    public async Task Expiry_does_nothing_before_the_window_elapses()
    {
        var h = new Harness();
        var request = await h.RequestAsync();
        await h.Service.ApproveAsync(h.Approver, request.RequestId, TimeSpan.FromHours(1), default);

        h.Clock.Advance(TimeSpan.FromMinutes(59));

        Assert.Equal(0, await h.ExpireDueAsync());
        Assert.Equal(SessionState.Active, h.Session.State);
    }

    [Fact]
    public async Task Requester_can_cancel_but_another_analyst_cannot()
    {
        var h = new Harness();
        var request = await h.RequestAsync();
        var other = h.Analyst with { UserObjectId = "oid-other" };

        // Ownership is checked before state, so a non-requester gets the same refusal whatever
        // state the request is in — and the same one they get for a request id that does not
        // exist. Refusing on state first would answer "409, already decided" for a decided request
        // and "403" for an undecided one, which tells a stranger about a request they cannot see.
        var denied = await Assert.ThrowsAsync<SensitiveSessionAuthorizationException>(
            () => h.Service.CancelAsync(other, request.RequestId, default));
        Assert.Equal(SensitiveSessionDenialReason.NotRequester, denied.Reason);

        var invented = await Assert.ThrowsAsync<SensitiveSessionAuthorizationException>(
            () => h.Service.CancelAsync(other, Guid.NewGuid(), default));
        Assert.Equal(SensitiveSessionDenialReason.RequestNotFound, invented.Reason);

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

    [Fact]
    public async Task Expiry_does_not_terminate_a_session_whose_lease_already_lapsed()
    {
        var h = new Harness();
        var request = await h.RequestAsync();
        await h.Service.ApproveAsync(h.Approver, request.RequestId, TimeSpan.FromHours(2), default);
        await h.Service.ActivateAsync(h.Analyst, request.RequestId, default);

        // Past the approval window AND past the 8-hour session lease. This harness does not run
        // M4-12's own sweeper (it is testing SensitiveSessionService in isolation), so the session
        // row still reads State = Active here the way it would in the up-to-5-minute window before
        // that sweeper next runs in production — and this service must not depend on the sweeper
        // having already caught it: it reads IsUsableAt directly rather than State == Active (D-06a),
        // so revoking here would write a session_revoked event for an action that changed nothing
        // real.
        h.Clock.Advance(TimeSpan.FromHours(9));
        Assert.Equal(1, await h.ExpireDueAsync());

        Assert.Equal(SensitiveSessionState.Ended,
            (await h.Service.GetAsync(h.Analyst, request.RequestId, default)).State);
        Assert.NotEqual(SessionState.Revoked, h.Session.State);
    }

    [Fact]
    public async Task Activation_and_cancellation_require_the_analyst_role_at_the_service()
    {
        // Not merely the route policy: that is built from Mina:Session:AnalystRole while this
        // workflow reads Mina:SensitiveSession:AnalystRole. Equal by default, and nothing keeps
        // them equal — so the check belongs where the decision is made.
        var h = new Harness();
        var request = await h.RequestAsync();
        await h.Service.ApproveAsync(h.Approver, request.RequestId, TimeSpan.FromHours(1), default);

        var roleless = h.Analyst with { Roles = new HashSet<string>() };

        var activate = await Assert.ThrowsAsync<SensitiveSessionAuthorizationException>(
            () => h.Service.ActivateAsync(roleless, request.RequestId, default));
        Assert.Equal(SensitiveSessionDenialReason.NotAuthorisedRole, activate.Reason);

        var cancel = await Assert.ThrowsAsync<SensitiveSessionAuthorizationException>(
            () => h.Service.CancelAsync(roleless, request.RequestId, default));
        Assert.Equal(SensitiveSessionDenialReason.NotAuthorisedRole, cancel.Reason);

        // The suppression never engaged.
        Assert.Equal(SessionMode.Normal, h.Session.Mode);
    }

    [Fact]
    public async Task A_session_may_have_only_one_undecided_request_at_a_time()
    {
        // Nothing else bounds how many requests an analyst can raise, and the approver queue is the
        // one place where one analyst's volume buries another's. A flood gains the flooder nothing
        // but can push a colleague's genuine request past the page an approver reads.
        var h = new Harness();
        await h.RequestAsync("CASE-1");

        var ex = await Assert.ThrowsAsync<SensitiveSessionRuleViolationException>(
            () => h.RequestAsync("CASE-2"));
        Assert.Equal(SensitiveSessionRule.RequestAlreadyPending, ex.Rule);

        // Once decided, the analyst may ask again — the rule is one *undecided* request, not one
        // request ever. Denial is a normal outcome and must not lock them out of asking.
        var pending = (await h.Service.ListPendingAsync(h.Approver, default)).Requests.Single();
        await h.Service.DenyAsync(h.Approver, pending.RequestId, default);

        var second = await h.RequestAsync("CASE-3");
        Assert.Equal(SensitiveSessionState.Requested, second.State);
    }

    [Fact]
    public async Task The_approver_queue_can_be_paged_past_the_first_screen()
    {
        // Truncation was reported before paging existed, which told an approver there was more
        // without giving them any way to reach it.
        var h = new Harness(queuePageSize: 2);
        var ids = new List<Guid>();
        for (var i = 0; i < 5; i++)
        {
            // One undecided request per session, so each needs its own session — and each needs a
            // distinct RequestedAt, or "oldest first" has nothing to order by and the assertion
            // would depend on dictionary iteration order.
            ids.Add((await h.RequestOnNewSessionAsync($"CASE-{i}")).RequestId);
            h.Clock.Advance(TimeSpan.FromMinutes(1));
        }

        var first = await h.Service.ListPendingAsync(h.Approver, default);
        Assert.Equal(ids.Take(2), first.Requests.Select(r => r.RequestId));
        Assert.True(first.HasMore);

        var second = await h.Service.ListPendingAsync(h.Approver, default, offset: 2);
        Assert.Equal(ids.Skip(2).Take(2), second.Requests.Select(r => r.RequestId));
        Assert.True(second.HasMore);
        Assert.Equal(2, second.Offset);

        var last = await h.Service.ListPendingAsync(h.Approver, default, offset: 4);
        Assert.Equal(ids.Skip(4), last.Requests.Select(r => r.RequestId));
        Assert.False(last.HasMore);
    }

    private sealed class Harness
    {
        public Harness(int queuePageSize = 100)
        {
            Session = ResearchSession.Issue(
                SessionId, "oid-analyst", "analyst@example.org", "device-1", "westeurope",
                T0, TimeSpan.FromHours(8), "SERIAL-1");
            Sessions.AddAsync(Session, default).GetAwaiter().GetResult();

            Service = new SensitiveSessionService(
                Requests, Sessions, NullSensitiveSessionAuditSink.Instance, NullSessionAuditSink.Instance,
                new InMemoryUnitOfWork(),
                Options.Create(new SensitiveSessionOptions { ApproverQueuePageSize = queuePageSize }),
                Clock);
        }

        /// <summary>
        /// A request on a session of its own. Needed wherever a test wants several undecided
        /// requests at once, since one session may only have one.
        /// </summary>
        public async Task<SensitiveSessionView> RequestOnNewSessionAsync(string reference)
        {
            var sessionId = Guid.NewGuid();
            await Sessions.AddAsync(
                ResearchSession.Issue(
                    sessionId, Analyst.UserObjectId, Analyst.UserPrincipalName, "device-1", "westeurope",
                    Clock.GetUtcNow(), TimeSpan.FromHours(8), $"SERIAL-{sessionId:N}"),
                default);

            return await Service.RequestAsync(
                Analyst, sessionId, reference, TimeSpan.FromHours(2), default);
        }

        public Guid SessionId { get; } = Guid.NewGuid();

        public ResearchSession Session { get; }

        public InMemorySessions Sessions { get; } = new();

        public InMemoryRequests Requests { get; } = new();

        public FakeClock Clock { get; } = new(T0);

        public SensitiveSessionService Service { get; }

        public SessionPrincipal Analyst =>
            new("oid-analyst", "analyst@example.org", "device-1", new HashSet<string> { "Mina.Analyst" }, true);

        public SessionPrincipal Approver =>
            new("oid-manager", "manager@example.org", "device-2", new HashSet<string> { "Mina.Approver" }, true);

        public Task<SensitiveSessionView> RequestAsync(string reference = "CASE-2026-0042") =>
            Service.RequestAsync(Analyst, SessionId, reference, TimeSpan.FromHours(2), default);

        /// <summary>What one pass of the expiry sweeper does, minus the per-request scoping.</summary>
        public async Task<int> ExpireDueAsync()
        {
            var expired = 0;
            foreach (var id in await Service.ListDueForExpiryAsync(default))
            {
                if (await Service.ExpireAsync(id, default))
                {
                    expired++;
                }
            }

            return expired;
        }
    }

    private sealed class FakeClock(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset _now = now;

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan by) => _now += by;
    }

    private sealed class InMemorySessions : ISessionRepository
    {
        public Task<IReadOnlyList<ResearchSession>> ListLapsedAsync(
            DateTimeOffset asOf, int limit, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<ResearchSession>>(
                [.. _store.Values
                    .Where(s => s.State == SessionState.Active && s.LeaseExpiresAt <= asOf)
                    .OrderBy(s => s.LeaseExpiresAt)
                    .Take(limit)]);

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

        public Task<bool> HasUndecidedRequestAsync(Guid sessionId, CancellationToken cancellationToken) =>
            Task.FromResult(_store.Values.Any(
                r => r.SessionId == sessionId && r.State == SensitiveSessionState.Requested));

        public Task<PendingRequestPage> ListPendingAsync(
            int offset, int limit, CancellationToken cancellationToken)
        {
            var page = _store.Values
                .Where(r => r.State == SensitiveSessionState.Requested)
                .OrderBy(r => r.RequestedAt)
                .Skip(offset)
                .Take(limit + 1)
                .ToList();

            return Task.FromResult(page.Count > limit
                ? new PendingRequestPage(page.Take(limit).ToList(), HasMore: true)
                : new PendingRequestPage(page, HasMore: false));
        }

        public Task<int> CountPendingAsync(CancellationToken cancellationToken) =>
            Task.FromResult(_store.Values.Count(r => r.State == SensitiveSessionState.Requested));

        public Task<IReadOnlyList<SensitiveSessionRequest>> ListForSessionAsync(
            Guid sessionId, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<SensitiveSessionRequest>>(
                [.. _store.Values.Where(r => r.SessionId == sessionId)]);

        public Task<IReadOnlyList<SensitiveSessionRequest>> ListExpiredAsync(
            DateTimeOffset asOf, int limit, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<SensitiveSessionRequest>>(
                [.. _store.Values
                    .Where(r => r.State is SensitiveSessionState.Approved or SensitiveSessionState.ActiveSuppressed
                                && r.ExpiresAt is not null && r.ExpiresAt <= asOf)
                    .OrderBy(r => r.ExpiresAt)
                    .Take(limit)]);
    }
}
