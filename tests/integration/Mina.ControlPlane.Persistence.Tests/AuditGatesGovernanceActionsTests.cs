using System.Data.Common;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
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
/// "No governance action proceeds unlogged" is the claim the whole audit design rests on
/// (CLAUDE.md, THREAT_MODEL, ADR-0003), and it was asserted nowhere. These make the audit INSERT
/// itself fail and check that the action it describes did not take effect either.
/// </summary>
/// <remarks>
/// Injecting the failure at the database — a command interceptor that refuses the audit INSERT —
/// rather than with a throwing sink is deliberate. A sink that throws before delegating never
/// reaches <see cref="EfAuditEventStore"/>, so it cannot detect the failure mode that actually
/// matters here: the audit append shares the request's <c>DbContext</c>, so appending flushes every
/// pending domain mutation with it. Whether the action is undone by a failed audit write therefore
/// depends on the ORDER of the mutation, the audit call and the commit — which is invisible to a
/// test that stubs the sink out.
/// </remarks>
public sealed class AuditGatesGovernanceActionsTests : IDisposable
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 1, 9, 0, 0, TimeSpan.Zero);

    private readonly SqliteConnection _connection;
    private readonly RefuseAuditInsertInterceptor _interceptor = new();

    public AuditGatesGovernanceActionsTests()
    {
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();
        using var context = CreateContext();
        context.Database.EnsureCreated();
    }

    public void Dispose() => _connection.Dispose();

    private MinaDbContext CreateContext() =>
        new(new DbContextOptionsBuilder<MinaDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(_interceptor)
            .Options);

    [Fact]
    public async Task A_suppression_approval_whose_audit_write_fails_does_not_take_effect()
    {
        Guid requestId;
        await using (var context = CreateContext())
        {
            requestId = (await SeedRequestAsync(context)).Id;
        }

        await using (var context = CreateContext())
        {
            var service = Service(context);
            _interceptor.Refuse();

            await Assert.ThrowsAsync<AuditWriteException>(
                () => service.ApproveAsync(Approver, requestId, TimeSpan.FromHours(1), default));
        }

        _interceptor.Allow();
        await using (var verify = CreateContext())
        {
            var request = await new EfSensitiveSessionRepository(verify).FindAsync(requestId, default);
            Assert.Equal(SensitiveSessionState.Requested, request!.State);
            Assert.Null(request.ApproverObjectId);
            Assert.Empty(await new EfAuditEventStore(verify).ReadAsync(0, 100, default));
        }
    }

    [Fact]
    public async Task An_expiry_whose_audit_write_fails_leaves_the_approval_due_and_the_session_suppressed()
    {
        // The dangerous shape: expiry both ends the approval and revokes its session. A partial
        // apply would leave an approval recorded as Ended with a live, still-suppressed session —
        // and the due query filters on Approved/ActiveSuppressed, so no later sweep would retry it.
        Guid requestId;
        Guid sessionId;
        await using (var context = CreateContext())
        {
            var request = await SeedRequestAsync(context);
            requestId = request.Id;
            sessionId = request.SessionId;

            var service = Service(context, T0);
            await service.ApproveAsync(Approver, requestId, TimeSpan.FromMinutes(30), default);
            await service.ActivateAsync(Analyst, requestId, default);
        }

        await using (var context = CreateContext())
        {
            var service = Service(context, T0.AddHours(1));
            _interceptor.Refuse();

            await Assert.ThrowsAsync<AuditWriteException>(() => service.ExpireAsync(requestId, default));
        }

        _interceptor.Allow();
        await using (var verify = CreateContext())
        {
            var request = await new EfSensitiveSessionRepository(verify).FindAsync(requestId, default);
            var session = await new EfSessionRepository(verify).FindAsync(sessionId, default);

            Assert.Equal(SensitiveSessionState.ActiveSuppressed, request!.State);
            Assert.Equal(SessionState.Active, session!.State);
            Assert.Equal(SessionMode.Sensitive, session.Mode);

            // Still due, so the next sweep retries it rather than the window being lost for good.
            var due = await new EfSensitiveSessionRepository(verify)
                .ListExpiredAsync(T0.AddHours(1), 100, default);
            Assert.Equal([requestId], due.Select(r => r.Id));
        }
    }

    [Fact]
    public async Task A_suppression_mismatch_that_cannot_be_audited_does_not_get_its_traffic_stored()
    {
        // Threat N5: a node still reporting destinations for a suppressed session. The hostnames are
        // discarded either way, so the audit event is the only surviving record that it happened.
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
                new PersistentTelemetryAuditSink(
                    new AuditWriter(
                        new EfAuditEventStore(context),
                        Options.Create(new AuditOptions { Environment = "test" }),
                        new Fixed(T0))));

            _interceptor.Refuse();
            await Assert.ThrowsAsync<AuditWriteException>(() => ingest.IngestAsync(
                new TelemetryBatch("westeurope", [
                    new TelemetryItem(sessionId, T0, "leaked-destination.example", 443, 10, 20, 5),
                ]),
                default));
        }

        _interceptor.Allow();
        await using (var verify = CreateContext())
        {
            var telemetry = new EfTelemetryRepository(verify);
            Assert.Empty(await telemetry.ListSuppressedForSessionAsync(sessionId, default));
            Assert.Empty(await telemetry.ListForSessionAsync(sessionId, default));
        }
    }

    private static SessionPrincipal Analyst =>
        new("oid-analyst", "analyst@fiaumalta.org", "device-1", new HashSet<string> { "Mina.Analyst" }, true);

    private static SessionPrincipal Approver =>
        new("oid-manager", "manager@fiaumalta.org", "device-2", new HashSet<string> { "Mina.Approver" }, true);

    private static SensitiveSessionService Service(MinaDbContext context, DateTimeOffset? now = null) =>
        new(new EfSensitiveSessionRepository(context),
            new EfSessionRepository(context),
            new PersistentSensitiveSessionAuditSink(
                new AuditWriter(
                    new EfAuditEventStore(context),
                    Options.Create(new AuditOptions { Environment = "test" }),
                    new Fixed(now ?? T0))),
            new EfUnitOfWork(context),
            Options.Create(new SensitiveSessionOptions()),
            new Fixed(now ?? T0));

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

    /// <summary>Fails exactly one kind of statement, leaving every other one alone.</summary>
    private sealed class RefuseAuditInsertInterceptor : DbCommandInterceptor
    {
        private string[]? _refusing;

        /// <summary>Refuse the audit chain's own insert.</summary>
        public void Refuse() => _refusing = ["INSERT", "Events"];

        /// <summary>Refuse a specific statement, so a mid-transaction failure can be placed exactly.</summary>
        public void Refuse(params string[] fragments) => _refusing = fragments;

        public void Allow() => _refusing = null;

        public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(
            DbCommand command,
            CommandEventData eventData,
            InterceptionResult<DbDataReader> result,
            CancellationToken cancellationToken = default)
        {
            Guard(command);
            return base.ReaderExecutingAsync(command, eventData, result, cancellationToken);
        }

        public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(
            DbCommand command,
            CommandEventData eventData,
            InterceptionResult<int> result,
            CancellationToken cancellationToken = default)
        {
            Guard(command);
            return base.NonQueryExecutingAsync(command, eventData, result, cancellationToken);
        }

        private void Guard(DbCommand command)
        {
            if (_refusing is not null
                && _refusing.All(f => command.CommandText.Contains(f, StringComparison.OrdinalIgnoreCase)))
            {
                throw new SqliteException($"simulated failure of: {string.Join(' ', _refusing)}", 1);
            }
        }
    }

    [Fact]
    public async Task An_expiry_that_cannot_revoke_the_session_does_not_record_the_approval_as_ended()
    {
        // The partial-apply that the "one commit" comment claimed was impossible. Appending the
        // audit event flushes the whole unit of work, so with the revoke sequenced AFTER the audit
        // write the expiry committed on its own and only the revoke was left for a second commit.
        // When that commit failed the approval was Ended with its session still live and still
        // suppressed — and the due query filters on Approved/ActiveSuppressed, so the sweeper could
        // never pick it up again. Failing the session UPDATE is what exposes it; failing the audit
        // insert does not, because then nothing commits at all.
        Guid requestId;
        Guid sessionId;
        await using (var context = CreateContext())
        {
            var request = await SeedRequestAsync(context);
            requestId = request.Id;
            sessionId = request.SessionId;

            var service = Service(context, T0);
            await service.ApproveAsync(Approver, requestId, TimeSpan.FromMinutes(30), default);
            await service.ActivateAsync(Analyst, requestId, default);
        }

        await using (var context = CreateContext())
        {
            var service = Service(context, T0.AddHours(1));
            _interceptor.Refuse("UPDATE", "Sessions");

            await Assert.ThrowsAnyAsync<Exception>(() => service.ExpireAsync(requestId, default));
        }

        _interceptor.Allow();
        await using (var verify = CreateContext())
        {
            var request = await new EfSensitiveSessionRepository(verify).FindAsync(requestId, default);
            var session = await new EfSessionRepository(verify).FindAsync(sessionId, default);

            // Either both happened or neither did. Nothing in between.
            Assert.Equal(SensitiveSessionState.ActiveSuppressed, request!.State);
            Assert.Equal(SessionState.Active, session!.State);

            var due = await new EfSensitiveSessionRepository(verify)
                .ListExpiredAsync(T0.AddHours(1), 100, default);
            Assert.Equal([requestId], due.Select(r => r.Id));

            // And no event claims a termination that did not happen.
            var events = await new EfAuditEventStore(verify).ReadAsync(0, 100, default);
            Assert.DoesNotContain(events, e => e.EventType == "sensitive_expired");
        }
    }
}
