using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using Mina.ControlPlane.Application.Sessions;
using Mina.ControlPlane.Domain.Regions;
using Mina.ControlPlane.Domain.Sessions;
using Mina.ControlPlane.Persistence;
using Mina.ControlPlane.Pki;

namespace Mina.ControlPlane.Persistence.Tests;

/// <summary>
/// Runs the real <see cref="SessionService"/> against the EF repository. The unit tests use an
/// in-memory store, so these prove the piece that only shows up with EF: the service's
/// load → mutate → update flow keeps the aggregate attached to the same context, which is what the
/// repository requires to enforce optimistic concurrency.
/// </summary>
public sealed class SessionServiceOverEfTests(SqliteDatabaseFixture db, TestCertificateAuthorityFixture ca)
    : IClassFixture<SqliteDatabaseFixture>, IClassFixture<TestCertificateAuthorityFixture>
{
    private static readonly DateTimeOffset T0 = new(2026, 8, 31, 9, 0, 0, TimeSpan.Zero);

    private readonly SqliteDatabaseFixture _db = db;
    private readonly CertificateAuthority _ca = ca.Authority;

    private (SessionService Service, MinaDbContext Context) CreateService(FakeClock clock)
    {
        var context = _db.CreateContext();
        var service = new SessionService(
            new RegionPolicy(["westeurope", "francecentral"], ["westeurope"]),
            new SessionCertificateIssuer(_ca, new SessionCertificatePolicy(TimeSpan.FromMinutes(60))),
            new EfSessionRepository(context),
            new StubEgressDirectory(),
            NullSessionAuditSink.Instance,
            Options.Create(new SessionServiceOptions()),
            clock);
        return (service, context);
    }

    private static SessionPrincipal Analyst =>
        new("oid-1", "analyst@fiaumalta.org", "device-1", new HashSet<string> { "Mina.Analyst" }, true);

    private static byte[] NewCsr()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return new CertificateRequest("CN=agent", key, HashAlgorithmName.SHA256).CreateSigningRequest();
    }

    [Fact]
    public async Task Issued_session_is_durable_across_contexts()
    {
        var clock = new FakeClock(T0);
        Guid sessionId;

        var (service, context) = CreateService(clock);
        await using (context)
        {
            var grant = await service.IssueAsync(Analyst, new SessionIssueRequest("westeurope", NewCsr()), default);
            sessionId = grant.SessionId;
        }

        // A brand-new context sees the committed session — it is in the database, not just memory.
        await using var verify = _db.CreateContext();
        var stored = await new EfSessionRepository(verify).FindAsync(sessionId, default);
        Assert.NotNull(stored);
        Assert.Equal("oid-1", stored.UserObjectId);
        Assert.Equal(SessionState.Active, stored.State);
    }

    [Fact]
    public async Task Issue_renew_end_lifecycle_persists_each_step()
    {
        var clock = new FakeClock(T0);
        Guid sessionId;
        string firstSerial;

        var (issueService, issueContext) = CreateService(clock);
        await using (issueContext)
        {
            var grant = await issueService.IssueAsync(Analyst, new SessionIssueRequest("westeurope", NewCsr()), default);
            sessionId = grant.SessionId;
            firstSerial = grant.CertificateSerialNumber;
        }

        clock.Advance(TimeSpan.FromMinutes(50));
        var (renewService, renewContext) = CreateService(clock);
        await using (renewContext)
        {
            var renewed = await renewService.RenewAsync(Analyst, sessionId, NewCsr(), default);
            Assert.NotEqual(firstSerial, renewed.CertificateSerialNumber);
            Assert.Equal(clock.GetUtcNow() + TimeSpan.FromMinutes(60), renewed.LeaseExpiresAt);
        }

        var (endService, endContext) = CreateService(clock);
        await using (endContext)
        {
            await endService.EndAsync(Analyst, sessionId, SessionEndReason.EndedByUser, default);
        }

        await using var verify = _db.CreateContext();
        var stored = await new EfSessionRepository(verify).FindAsync(sessionId, default);
        Assert.Equal(SessionState.Ended, stored!.State);
        Assert.Equal(SessionEndReason.EndedByUser, stored.EndReason);
    }

    [Fact]
    public async Task A_session_stored_by_one_user_cannot_be_renewed_by_another()
    {
        var clock = new FakeClock(T0);
        Guid sessionId;

        var (service, context) = CreateService(clock);
        await using (context)
        {
            sessionId = (await service.IssueAsync(Analyst, new SessionIssueRequest("westeurope", NewCsr()), default))
                .SessionId;
        }

        var other = Analyst with { UserObjectId = "oid-2", UserPrincipalName = "other@fiaumalta.org" };
        var (otherService, otherContext) = CreateService(clock);
        await using (otherContext)
        {
            var ex = await Assert.ThrowsAsync<SessionAuthorizationException>(
                () => otherService.RenewAsync(other, sessionId, NewCsr(), default));
            Assert.Equal(SessionDenialReason.NotSessionOwner, ex.Reason);
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
        public EgressEndpointInfo? Resolve(string region) =>
            region == "westeurope" ? new EgressEndpointInfo("20.0.0.1", 443, "westeurope.egress.mina") : null;
    }
}
