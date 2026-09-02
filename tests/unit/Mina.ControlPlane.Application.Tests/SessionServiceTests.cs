using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using Mina.ControlPlane.Application.Audit;
using Mina.ControlPlane.Application.Sessions;
using Mina.ControlPlane.Domain.Regions;
using Mina.ControlPlane.Domain.Sessions;
using Mina.ControlPlane.Persistence;
using Mina.ControlPlane.Pki;

namespace Mina.ControlPlane.Application.Tests;

public class SessionServiceTests
{
    private static readonly DateTimeOffset T0 = new(2026, 8, 31, 9, 0, 0, TimeSpan.Zero);
    private const string Analyst = "Mina.Analyst";

    [Fact]
    public async Task Issue_grants_a_session_for_an_authorised_analyst_on_a_selectable_region()
    {
        var h = new Harness();
        var principal = h.Analyst();

        var grant = await h.Service.IssueAsync(principal, h.Request("westeurope"), default);

        Assert.NotEqual(Guid.Empty, grant.SessionId);
        Assert.Equal("westeurope", grant.Region);
        Assert.Equal(T0 + TimeSpan.FromMinutes(60), grant.LeaseExpiresAt);
        Assert.Equal(new EgressEndpointInfo("20.0.0.1", 443, "westeurope.egress.mina"), grant.Egress);

        // The grant carries a real, CA-signed client certificate bound to the session.
        using var cert = X509CertificateLoader.LoadCertificate(grant.IssuedCertificate);
        var san = cert.Extensions.OfType<X509SubjectAlternativeNameExtension>().Single().Format(false);
        Assert.Contains($"mina:session:{grant.SessionId:D}", san, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(grant.SessionId, h.Audit.Started);
    }

    [Fact]
    public async Task Issue_denies_a_caller_without_the_analyst_role()
    {
        var h = new Harness();
        var principal = h.Analyst() with { Roles = new HashSet<string> { "Mina.Approver" } };

        var ex = await Assert.ThrowsAsync<SessionAuthorizationException>(
            () => h.Service.IssueAsync(principal, h.Request("westeurope"), default));

        Assert.Equal(SessionDenialReason.NotAuthorisedRole, ex.Reason);
        Assert.Contains((SessionDenialReason.NotAuthorisedRole, "westeurope"), h.Audit.Denials);
    }

    [Fact]
    public async Task Issue_denies_a_token_that_is_not_device_bound()
    {
        var h = new Harness();
        var principal = h.Analyst() with { DeviceBound = false };

        var ex = await Assert.ThrowsAsync<SessionAuthorizationException>(
            () => h.Service.IssueAsync(principal, h.Request("westeurope"), default));

        // Named for what the check actually proves: the token came from a device-bound flow on a
        // registered device. It is not evidence of Intune compliance — see the auth-context tests.
        Assert.Equal(SessionDenialReason.DeviceNotBound, ex.Reason);
    }

    [Fact]
    public async Task Without_an_auth_context_configured_a_device_bound_token_is_enough()
    {
        // The default deployment shape: no authentication context set, so behaviour is unchanged.
        var h = new Harness();

        var grant = await h.Service.IssueAsync(h.Analyst(), h.Request("westeurope"), default);

        Assert.NotEqual(Guid.Empty, grant.SessionId);
    }

    [Fact]
    public async Task A_required_auth_context_is_demanded_even_from_a_device_bound_token()
    {
        // A deviceid proves registration, not compliance: a registered device failing its Intune
        // policy emits exactly the same claim. When the deployment binds a Conditional Access
        // policy to an authentication context, the token must carry it.
        var h = new Harness(authContextId: "c1");
        var registeredButUnproven = h.Analyst();

        var ex = await Assert.ThrowsAsync<SessionAuthorizationException>(
            () => h.Service.IssueAsync(registeredButUnproven, h.Request("westeurope"), default));

        Assert.Equal(SessionDenialReason.AuthenticationContextRequired, ex.Reason);
    }

    [Fact]
    public async Task A_token_carrying_the_required_auth_context_is_issued_a_session()
    {
        var h = new Harness(authContextId: "c1");
        var stepped = h.Analyst() with { AuthenticationContexts = new HashSet<string> { "c1" } };

        var grant = await h.Service.IssueAsync(stepped, h.Request("westeurope"), default);

        Assert.NotEqual(Guid.Empty, grant.SessionId);
    }

    [Fact]
    public async Task A_different_auth_context_does_not_satisfy_the_requirement()
    {
        // Another policy's context must not stand in for the compliance one.
        var h = new Harness(authContextId: "c1");
        var wrongContext = h.Analyst() with { AuthenticationContexts = new HashSet<string> { "c2" } };

        var ex = await Assert.ThrowsAsync<SessionAuthorizationException>(
            () => h.Service.IssueAsync(wrongContext, h.Request("westeurope"), default));

        Assert.Equal(SessionDenialReason.AuthenticationContextRequired, ex.Reason);
    }

    [Theory]
    [InlineData("francecentral")] // approved but no active stamp
    [InlineData("eastus")]        // not approved at all
    public async Task Issue_denies_an_unselectable_region(string region)
    {
        var h = new Harness();

        var ex = await Assert.ThrowsAsync<SessionAuthorizationException>(
            () => h.Service.IssueAsync(h.Analyst(), h.Request(region), default));

        Assert.Equal(SessionDenialReason.RegionNotSelectable, ex.Reason);
    }

    [Fact]
    public async Task Issue_rejects_a_malformed_csr()
    {
        var h = new Harness();
        var request = new SessionIssueRequest("westeurope", [1, 2, 3, 4]);

        var ex = await Assert.ThrowsAsync<SessionAuthorizationException>(
            () => h.Service.IssueAsync(h.Analyst(), request, default));

        Assert.Equal(SessionDenialReason.InvalidCertificateRequest, ex.Reason);
    }

    [Fact]
    public async Task Renew_extends_the_lease_for_the_owner()
    {
        var h = new Harness();
        var grant = await h.Service.IssueAsync(h.Analyst(), h.Request("westeurope"), default);

        h.Clock.Advance(TimeSpan.FromMinutes(50));
        var renewed = await h.Service.RenewAsync(h.Analyst(), grant.SessionId, h.NewCsr(), default);

        Assert.Equal(grant.SessionId, renewed.SessionId);
        Assert.Equal(T0.AddMinutes(50) + TimeSpan.FromMinutes(60), renewed.LeaseExpiresAt);
        Assert.Contains(grant.SessionId, h.Audit.Renewed);
    }

    [Fact]
    public async Task Renew_by_a_different_user_is_denied_as_not_owner()
    {
        var h = new Harness();
        var grant = await h.Service.IssueAsync(h.Analyst(), h.Request("westeurope"), default);
        var other = h.Analyst() with { UserObjectId = "oid-2", UserPrincipalName = "other@fiaumalta.org" };

        var ex = await Assert.ThrowsAsync<SessionAuthorizationException>(
            () => h.Service.RenewAsync(other, grant.SessionId, h.NewCsr(), default));

        Assert.Equal(SessionDenialReason.NotSessionOwner, ex.Reason);
    }

    [Fact]
    public async Task End_marks_the_session_ended_for_the_owner()
    {
        var h = new Harness();
        var grant = await h.Service.IssueAsync(h.Analyst(), h.Request("westeurope"), default);

        await h.Service.EndAsync(h.Analyst(), grant.SessionId, SessionEndReason.EndedByUser, default);

        var stored = await h.Repository.FindAsync(grant.SessionId, default);
        Assert.Equal(SessionState.Ended, stored!.State);
        Assert.Contains(grant.SessionId, h.Audit.Ended);
    }

    [Fact]
    public async Task Renew_of_an_unknown_session_reports_not_found()
    {
        var h = new Harness();

        var ex = await Assert.ThrowsAsync<SessionAuthorizationException>(
            () => h.Service.RenewAsync(h.Analyst(), Guid.NewGuid(), h.NewCsr(), default));

        Assert.Equal(SessionDenialReason.SessionNotFound, ex.Reason);
    }

    [Fact]
    public async Task A_lapsed_session_is_closed_and_emits_its_terminal_event()
    {
        // ResearchSession.TryExpire had no production caller, so a session that simply ran out
        // stayed State = Active for ever: no terminal event, an active-session set that only grew,
        // and every query reasoning about "active" returning sessions that died hours ago.
        var h = new Harness();
        var grant = await h.Service.IssueAsync(h.Analyst(), h.Request("westeurope"), default);

        h.Clock.Advance(TimeSpan.FromMinutes(61));

        var lapsed = await h.Service.ListLapsedForExpiryAsync(default);
        Assert.Equal([grant.SessionId], lapsed);
        Assert.True(await h.Service.ExpireAsync(grant.SessionId, default));

        var stored = await h.Repository.FindAsync(grant.SessionId, default);
        Assert.Equal(SessionState.Expired, stored!.State);

        Assert.Contains(grant.SessionId, h.Audit.Ended);

        // Idempotent: a second sweep, or another instance racing this one, finds nothing to do.
        Assert.False(await h.Service.ExpireAsync(grant.SessionId, default));
        Assert.Empty(await h.Service.ListLapsedForExpiryAsync(default));
    }

    [Fact]
    public async Task A_session_inside_its_lease_is_left_alone()
    {
        var h = new Harness();
        var grant = await h.Service.IssueAsync(h.Analyst(), h.Request("westeurope"), default);

        h.Clock.Advance(TimeSpan.FromMinutes(59));

        Assert.Empty(await h.Service.ListLapsedForExpiryAsync(default));
        Assert.False(await h.Service.ExpireAsync(grant.SessionId, default));
        Assert.Equal(SessionState.Active, (await h.Repository.FindAsync(grant.SessionId, default))!.State);
    }

    [Fact]
    public async Task Expiry_writes_session_expired_rather_than_session_ended()
    {
        // The event type is decided in the real sink, so a recording fake cannot prove this.
        // `session_expired` was catalogued in EVENT_SCHEMAS and emitted by nothing, which meant a
        // SOC rule keyed on it could never have fired.
        var store = new InMemoryAuditEventStore();
        var writer = new AuditWriter(
            store, Options.Create(new AuditOptions { Environment = "test" }), new FakeClock(T0));
        var h = new Harness(audit: new PersistentSessionAuditSink(writer));

        var grant = await h.Service.IssueAsync(h.Analyst(), h.Request("westeurope"), default);
        h.Clock.Advance(TimeSpan.FromMinutes(61));
        Assert.True(await h.Service.ExpireAsync(grant.SessionId, default));

        var events = await store.ReadAsync(0, 100, default);
        Assert.Contains("session_expired", events.Select(e => e.EventType));
        Assert.DoesNotContain("session_ended", events.Select(e => e.EventType));
    }

    private sealed class Harness
    {
        public Harness(string authContextId = "", ISessionAuditSink? audit = null)
        {
            // Most tests assert against the recording fake; the one that checks which audit *event
            // type* expiry writes needs the real sink, because the fake does not decide that.
            var sink = audit ?? Audit;
            var regionPolicy = new RegionPolicy(
                ["westeurope", "northeurope", "germanywestcentral", "francecentral"],
                ["westeurope", "northeurope"]);
            Ca = CertificateAuthority.Create("Mina Test CA", T0.AddDays(-1), TimeSpan.FromDays(30));
            var issuer = new SessionCertificateIssuer(Ca, new SessionCertificatePolicy(TimeSpan.FromMinutes(60)));
            Clock = new FakeClock(T0);
            Service = new SessionService(
                regionPolicy, issuer, Repository, new StubEgressDirectory(), sink,
                Options.Create(new SessionServiceOptions { RequiredAuthContextId = authContextId }), Clock);
        }

        public CertificateAuthority Ca { get; }

        public InMemorySessionRepository Repository { get; } = new();

        public RecordingAudit Audit { get; } = new();

        public FakeClock Clock { get; }

        public SessionService Service { get; }

        public SessionPrincipal Analyst() =>
            new("oid-1", "analyst@fiaumalta.org", "device-1", new HashSet<string> { SessionServiceTests.Analyst }, true);

        public SessionIssueRequest Request(string region) => new(region, NewCsr());

        public byte[] NewCsr()
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            return new CertificateRequest("CN=agent", key, HashAlgorithmName.SHA256).CreateSigningRequest();
        }
    }

    private sealed class FakeClock(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset _now = now;

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan by) => _now += by;
    }

    private sealed class StubEgressDirectory : IEgressDirectory
    {
        public EgressEndpointInfo? Resolve(string region) => region switch
        {
            "westeurope" => new EgressEndpointInfo("20.0.0.1", 443, "westeurope.egress.mina"),
            "northeurope" => new EgressEndpointInfo("20.0.0.2", 443, "northeurope.egress.mina"),
            _ => null,
        };
    }

    private sealed class InMemorySessionRepository : ISessionRepository
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

    private sealed class RecordingAudit : ISessionAuditSink
    {
        public List<Guid> Started { get; } = [];

        public List<Guid> Renewed { get; } = [];

        public List<Guid> Ended { get; } = [];

        public List<(SessionDenialReason Reason, string? Region)> Denials { get; } = [];

        public Task SessionStartedAsync(ResearchSession session, CancellationToken cancellationToken)
        {
            Started.Add(session.Id);
            return Task.CompletedTask;
        }

        public Task SessionRenewedAsync(ResearchSession session, CancellationToken cancellationToken)
        {
            Renewed.Add(session.Id);
            return Task.CompletedTask;
        }

        public Task SessionEndedAsync(ResearchSession session, CancellationToken cancellationToken)
        {
            Ended.Add(session.Id);
            return Task.CompletedTask;
        }

        public Task AuthorizationDeniedAsync(
            SessionPrincipal principal, SessionDenialReason reason, string? region, CancellationToken cancellationToken)
        {
            Denials.Add((reason, region));
            return Task.CompletedTask;
        }
    }
}
