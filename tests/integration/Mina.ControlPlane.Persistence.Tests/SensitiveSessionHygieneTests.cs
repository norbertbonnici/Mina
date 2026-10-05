using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Mina.ControlPlane.Application.Audit;
using Mina.ControlPlane.Application.SensitiveSessions;
using Mina.ControlPlane.Application.Sessions;
using Mina.ControlPlane.Application.Telemetry;
using Mina.ControlPlane.Domain;
using Mina.ControlPlane.Domain.Audit;
using Mina.ControlPlane.Domain.SensitiveSessions;
using Mina.ControlPlane.Domain.Sessions;
using Mina.ControlPlane.Domain.Telemetry;

namespace Mina.ControlPlane.Persistence.Tests;

/// <summary>
/// M3-7: closes the specific gaps a survey of the existing per-feature test suites found before this
/// milestone -- every layer around suppression proves its own slice (domain transitions, service
/// authorisation, HTTP status codes, repository round-trips, audit-write atomicity), but nothing read
/// the actually-persisted content of the one event AC-012's second sentence names (a mismatch is
/// "critical"), and nothing checked LOGGING_AND_PRIVACY's full mandatory-field list against a real
/// suppressed session's real audit trail in one place, end to end. Both here, against a real
/// SQLite-backed <see cref="MinaDbContext"/>, not fakes -- content correctness is exactly what a fake
/// sink cannot prove.
/// </summary>
public sealed class SensitiveSessionHygieneTests : IDisposable
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 1, 9, 0, 0, TimeSpan.Zero);

    private readonly SqliteConnection _connection;

    public SensitiveSessionHygieneTests()
    {
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();
        using var context = CreateContext();
        context.Database.EnsureCreated();
    }

    public void Dispose() => _connection.Dispose();

    private MinaDbContext CreateContext() =>
        new(new DbContextOptionsBuilder<MinaDbContext>().UseSqlite(_connection).Options);

    [Fact]
    public async Task A_suppression_mismatch_is_recorded_with_the_documented_content()
    {
        Guid sessionId;
        await using (var context = CreateContext())
        {
            var request = await SeedRequestAsync(context);
            sessionId = request.SessionId;
            var service = Service(context, T0);
            await service.ApproveAsync(Approver, request.Id, TimeSpan.FromHours(2), default);
            await service.ActivateAsync(Analyst, request.Id, default);
        }

        await using (var context = CreateContext())
        {
            var ingest = new TelemetryIngestService(
                new EfTelemetryRepository(context),
                new EfSessionRepository(context),
                new PersistentTelemetryAuditSink(Writer(context, T0.AddMinutes(5))));

            await ingest.IngestAsync(
                new TelemetryBatch("westeurope", [
                    new TelemetryItem(sessionId, T0.AddMinutes(5), "leaked-during-suppression.example", 443, 10, 20, 5),
                ]),
                default);
        }

        await using (var verify = CreateContext())
        {
            // The hostname itself never reaches storage -- reduced to a count, per AC-012's first
            // sentence -- and the mismatch is the only surviving record that it was ever sent.
            var telemetry = new EfTelemetryRepository(verify);
            Assert.Empty(await telemetry.ListForSessionAsync(sessionId, default));
            var summary = Assert.Single(await telemetry.ListSuppressedForSessionAsync(sessionId, default));
            Assert.Equal(1, summary.ConnectionCount);

            var events = await new EfAuditEventStore(verify).ReadAsync(0, 100, default);
            var mismatch = Assert.Single(events, e => e.EventType == "sensitive_suppression_mismatch");

            // AC-012's own wording: the discrepancy "raises a critical event".
            Assert.Equal(AuditSeverity.Critical, mismatch.Severity);
            // EVENT_SCHEMAS.md documents this as control-plane -- the control plane's own ingest
            // logic detects and writes it, the node never emits an event of its own here, the same
            // as authz_denied or session_revoked being control-plane despite another actor
            // triggering them. Found tagged EgressNode instead while scoping this suite; fixed
            // alongside telemetry_region_mismatch and telemetry_unattributable, which shared the
            // same mistagging and were undocumented in EVENT_SCHEMAS.md entirely.
            Assert.Equal(AuditComponent.ControlPlane, mismatch.Component);
            Assert.Equal("westeurope", mismatch.Region);
            Assert.Equal(sessionId, mismatch.SessionId);
            Assert.Contains("\"discarded_items\":1", mismatch.Data, StringComparison.Ordinal);

            // The one property no fake sink can prove: the actually-persisted row, not a call the
            // fake recorded, never carries the destination it is reporting about.
            Assert.DoesNotContain("leaked-during-suppression.example", mismatch.Data, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task The_full_mandatory_audit_field_set_survives_a_suppressed_sessions_lifecycle()
    {
        // LOGGING_AND_PRIVACY.md's list, even during suppression: user identity; managed device
        // identity; session id and start/end; selected egress region; request and justification
        // reference; approver and decision; approval/expiry timestamps. (Administrative and
        // break-glass events are the same clause's last item; break-glass has no implementation yet
        // -- M4-5/M4-21 -- so there is nothing to exercise here, and this test does not claim
        // otherwise.) No single event carries the whole list -- session identity/device/region live
        // on session_started, which is C2 and never suppressible; the suppression trail adds the
        // rest -- so this reads the session's full trail and checks the union, matching how the
        // system is actually built rather than demanding one event duplicate every field.
        Guid sessionId;
        await using (var context = CreateContext())
        {
            sessionId = Guid.NewGuid();
            var session = ResearchSession.Issue(
                sessionId, Analyst.UserObjectId, Analyst.UserPrincipalName, "device-mandatory-7",
                "westeurope", T0, TimeSpan.FromHours(8), $"SERIAL-{sessionId:N}");
            await new EfSessionRepository(context).AddAsync(session, default);
            await new PersistentSessionAuditSink(Writer(context, T0)).SessionStartedAsync(session, default);

            // Through the service, not a direct repository seed -- RequestAsync is what writes
            // sensitive_requested, and this test's whole point is to prove that event's field
            // content, not just the transition it drives.
            var service = Service(context, T0);
            var view = await service.RequestAsync(
                Analyst, sessionId, "CASE-2026-0099", TimeSpan.FromHours(1), default);
            await service.ApproveAsync(Approver, view.RequestId, TimeSpan.FromMinutes(30), default);
            await service.ActivateAsync(Analyst, view.RequestId, default);
        }

        await using (var expire = CreateContext())
        {
            var due = await new EfSensitiveSessionRepository(expire)
                .ListExpiredAsync(T0.AddHours(1), 100, default);
            var service = Service(expire, T0.AddHours(1));
            foreach (var request in due)
            {
                await service.ExpireAsync(request.Id, default);
            }
        }

        await using (var verify = CreateContext())
        {
            var events = (await new EfAuditEventStore(verify).ReadAsync(0, 100, default))
                .Where(e => e.SessionId == sessionId)
                .ToList();

            var started = Assert.Single(events, e => e.EventType == "session_started");
            var requested = Assert.Single(events, e => e.EventType == "sensitive_requested");
            var approved = Assert.Single(events, e => e.EventType == "sensitive_approved");
            var expired = Assert.Single(events, e => e.EventType == "sensitive_expired");

            // User identity -- present on both the session's own trail and the suppression trail.
            Assert.Equal(Analyst.UserObjectId, started.UserObjectId);
            Assert.Equal(Analyst.UserPrincipalName, started.UserPrincipalName);
            Assert.Equal(Analyst.UserObjectId, requested.UserObjectId);

            // Managed device identity -- carried on session_started, never on the suppression
            // events themselves, which is why this has to read the joined trail rather than one row.
            Assert.Equal("device-mandatory-7", started.DeviceId);

            // Session id (implicit -- every event above was filtered on it) and egress region.
            Assert.Equal("westeurope", started.Region);

            // Request and justification reference.
            Assert.Contains("CASE-2026-0099", requested.Data, StringComparison.Ordinal);

            // Approver and decision, and the approval timestamp -- the approver's own identity lives
            // in the data payload, not the envelope's UserObjectId, which stays the requester's
            // throughout the whole suppression trail (see PersistentSensitiveSessionAuditSink.Write).
            Assert.Contains(Approver.UserPrincipalName, approved.Data, StringComparison.Ordinal);
            Assert.Contains("expires_at", approved.Data, StringComparison.Ordinal);

            // Expiry timestamp, and that suppression actually ended rather than merely being logged
            // as having ended: expiring an *activated* approval terminates the session outright
            // (D-06, LOGGING_AND_PRIVACY.md §4), not merely reverting its mode. session_revoked is
            // the "session end" half of "session id and start/end", the other event this trail is
            // required to retain.
            Assert.Equal(AuditSeverity.Notice, expired.Severity);
            var revoked = Assert.Single(events, e => e.EventType == "session_revoked");
            Assert.Equal(AuditSeverity.High, revoked.Severity);

            var session = await new EfSessionRepository(verify).FindAsync(sessionId, default);
            Assert.Equal(SessionState.Revoked, session!.State);
        }
    }

    private static SessionPrincipal Analyst =>
        new("oid-hygiene-analyst", "hygiene-analyst@example.org", "device-mandatory-7",
            new HashSet<string> { "Mina.Analyst" }, true);

    private static SessionPrincipal Approver =>
        new("oid-hygiene-approver", "hygiene-approver@example.org", "device-hygiene-mgr",
            new HashSet<string> { "Mina.Approver" }, true);

    private static SensitiveSessionService Service(MinaDbContext context, DateTimeOffset now) =>
        new(new EfSensitiveSessionRepository(context),
            new EfSessionRepository(context),
            new PersistentSensitiveSessionAuditSink(Writer(context, now)),
            new PersistentSessionAuditSink(Writer(context, now)),
            new EfUnitOfWork(context),
            Options.Create(new SensitiveSessionOptions()),
            new Fixed(now));

    private static AuditWriter Writer(MinaDbContext context, DateTimeOffset now) =>
        new(new EfAuditEventStore(context), Options.Create(new AuditOptions { Environment = "test" }), new Fixed(now));

    private async Task<SensitiveSessionRequest> SeedRequestAsync(MinaDbContext context)
    {
        var sessionId = Guid.NewGuid();
        await new EfSessionRepository(context).AddAsync(
            ResearchSession.Issue(
                sessionId, Analyst.UserObjectId, Analyst.UserPrincipalName, "device-1", "westeurope",
                T0, TimeSpan.FromHours(8), $"SERIAL-{sessionId:N}"),
            default);

        var request = SensitiveSessionRequest.Create(
            Guid.NewGuid(), sessionId, Analyst.UserObjectId, Analyst.UserPrincipalName,
            "CASE-2026-0042", TimeSpan.FromHours(1), new SensitiveSessionPolicy(TimeSpan.FromHours(4)), T0);
        await new EfSensitiveSessionRepository(context).AddAsync(request, default);
        return request;
    }

    private sealed class Fixed(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
