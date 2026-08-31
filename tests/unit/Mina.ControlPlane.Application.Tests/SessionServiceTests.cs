using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using Mina.ControlPlane.Application.Sessions;
using Mina.ControlPlane.Domain.Regions;
using Mina.ControlPlane.Domain.Sessions;
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
    public async Task Issue_denies_a_noncompliant_device()
    {
        var h = new Harness();
        var principal = h.Analyst() with { DeviceCompliant = false };

        var ex = await Assert.ThrowsAsync<SessionAuthorizationException>(
            () => h.Service.IssueAsync(principal, h.Request("westeurope"), default));

        Assert.Equal(SessionDenialReason.DeviceNotCompliant, ex.Reason);
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

    private sealed class Harness
    {
        public Harness()
        {
            var regionPolicy = new RegionPolicy(
                ["westeurope", "northeurope", "germanywestcentral", "francecentral"],
                ["westeurope", "northeurope"]);
            Ca = CertificateAuthority.Create("Mina Test CA", T0.AddDays(-1), TimeSpan.FromDays(30));
            var issuer = new SessionCertificateIssuer(Ca, new SessionCertificatePolicy(TimeSpan.FromMinutes(60)));
            Clock = new FakeClock(T0);
            Service = new SessionService(
                regionPolicy, issuer, Repository, new StubEgressDirectory(), Audit,
                Options.Create(new SessionServiceOptions()), Clock);
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
