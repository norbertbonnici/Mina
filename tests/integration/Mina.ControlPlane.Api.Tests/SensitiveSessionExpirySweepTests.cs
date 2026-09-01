using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Mina.ControlPlane.Api.Infrastructure;
using Mina.ControlPlane.Application.SensitiveSessions;
using Mina.ControlPlane.Application.Sessions;
using Mina.ControlPlane.Domain;
using Mina.ControlPlane.Domain.SensitiveSessions;
using Mina.ControlPlane.Domain.Sessions;
using Mina.ControlPlane.Persistence;

namespace Mina.ControlPlane.Api.Tests;

/// <summary>
/// The expiry sweeper is the only thing that stops suppression outliving its approved window
/// (AC-011), so it has to survive the failures a live database produces. These cover the two ways it
/// used to fail: one bad row taking the rest of the sweep with it, and the sweep taking the host
/// with it.
/// </summary>
/// <remarks>
/// Backed by real EF Core on SQLite rather than the in-memory stores. That matters here: the
/// in-memory stores hold the aggregate instances themselves, so a failed commit still "persists"
/// the mutation and every arrangement below would pass regardless of whether the sweeper isolates
/// anything.
/// </remarks>
public sealed class SensitiveSessionExpirySweepTests : IDisposable
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 1, 9, 0, 0, TimeSpan.Zero);

    private readonly Harness _h = new();

    public void Dispose() => _h.Dispose();

    [Fact]
    public async Task A_request_that_cannot_be_expired_leaves_the_others_to_expire_normally()
    {
        var poisoned = await _h.SuppressedSessionAsync();
        var healthy = await _h.SuppressedSessionAsync();
        _h.Audit.FailFor(poisoned.RequestId);

        _h.Clock.Advance(TimeSpan.FromHours(2));
        var (expired, failed) = await SensitiveSessionExpiryService.SweepAsync(
            _h.Scopes, NullLogger.Instance, default);

        Assert.Equal(1, expired);
        Assert.Equal(1, failed);

        // The healthy approval closed and, per D-06, took its session with it.
        Assert.Equal(SensitiveSessionState.Ended, await _h.RequestStateAsync(healthy.RequestId));
        Assert.Equal(SessionState.Revoked, await _h.SessionStateAsync(healthy.SessionId));
    }

    [Fact]
    public async Task A_failed_expiry_is_rolled_back_whole_rather_than_recorded_without_its_audit_event()
    {
        var poisoned = await _h.SuppressedSessionAsync();
        var healthy = await _h.SuppressedSessionAsync();
        _h.Audit.FailFor(poisoned.RequestId);

        _h.Clock.Advance(TimeSpan.FromHours(2));
        await SensitiveSessionExpiryService.SweepAsync(_h.Scopes, NullLogger.Instance, default);

        // Sharing one unit of work across the sweep would commit the poisoned request's expiry
        // alongside the healthy one — silently ending an approval with no audit event for it, which
        // is precisely the gap ADR-0003 exists to prevent. It must still be suppressing, and still
        // be due, so the next sweep retries it.
        Assert.Equal(SensitiveSessionState.ActiveSuppressed, await _h.RequestStateAsync(poisoned.RequestId));
        Assert.Equal(SessionState.Active, await _h.SessionStateAsync(poisoned.SessionId));
        Assert.Equal([poisoned.RequestId], await _h.DueAsync());
    }

    [Fact]
    public async Task A_failure_listing_due_requests_is_logged_rather_than_thrown_at_the_host()
    {
        // A BackgroundService that throws stops the whole host by default, which would take session
        // issuance down with it. The loop has to swallow and retry instead.
        _h.Clock.Advance(TimeSpan.FromHours(2));
        _h.BreakTheDatabase();

        var service = new SensitiveSessionExpiryService(
            _h.Scopes, NullLogger<SensitiveSessionExpiryService>.Instance, _h.Clock);
        using var cts = new CancellationTokenSource();

        await service.StartAsync(cts.Token);
        await cts.CancelAsync();
        await service.StopAsync(default);

        Assert.NotNull(service.ExecuteTask);
        Assert.Null(service.ExecuteTask!.Exception);
    }

    private sealed record Suppressed(Guid RequestId, Guid SessionId);

    private sealed class Harness : IDisposable
    {
        private readonly SqliteConnection _connection;
        private readonly ServiceProvider _provider;

        public Harness()
        {
            _connection = new SqliteConnection("DataSource=:memory:");
            _connection.Open();

            var services = new ServiceCollection();
            services.AddDbContext<MinaDbContext>(o => o.UseSqlite(_connection));
            services.AddScoped<ISessionRepository, EfSessionRepository>();
            services.AddScoped<ISensitiveSessionRepository, EfSensitiveSessionRepository>();
            services.AddScoped<IUnitOfWork, EfUnitOfWork>();
            services.AddScoped<SensitiveSessionService>();
            services.AddSingleton<ISensitiveSessionAuditSink>(Audit);
            services.AddSingleton(Options.Create(new SensitiveSessionOptions()));
            services.AddSingleton<TimeProvider>(Clock);

            _provider = services.BuildServiceProvider();
            Scopes = _provider.GetRequiredService<IServiceScopeFactory>();

            using var scope = Scopes.CreateScope();
            scope.ServiceProvider.GetRequiredService<MinaDbContext>().Database.EnsureCreated();
        }

        public FailableAuditSink Audit { get; } = new();

        public FakeClock Clock { get; } = new(T0);

        public IServiceScopeFactory Scopes { get; }

        /// <summary>An analyst asks, a manager approves, the analyst activates: one live suppression.</summary>
        public async Task<Suppressed> SuppressedSessionAsync()
        {
            var sessionId = Guid.NewGuid();
            using var scope = Scopes.CreateScope();
            var sessions = scope.ServiceProvider.GetRequiredService<ISessionRepository>();
            await sessions.AddAsync(
                ResearchSession.Issue(
                    sessionId, "oid-analyst", "analyst@fiaumalta.org", "device-1", "westeurope",
                    Clock.GetUtcNow(), TimeSpan.FromHours(8), $"SERIAL-{sessionId:N}"),
                default);
            await scope.ServiceProvider.GetRequiredService<IUnitOfWork>().CommitAsync(default);

            var service = scope.ServiceProvider.GetRequiredService<SensitiveSessionService>();
            var analyst = new SessionPrincipal(
                "oid-analyst", "analyst@fiaumalta.org", "device-1", new HashSet<string> { "Mina.Analyst" }, true);
            var approver = new SessionPrincipal(
                "oid-manager", "manager@fiaumalta.org", "device-2", new HashSet<string> { "Mina.Approver" }, true);

            var view = await service.RequestAsync(analyst, sessionId, "CASE-2026-0042", TimeSpan.FromHours(1), default);
            await service.ApproveAsync(approver, view.RequestId, TimeSpan.FromHours(1), default);
            await service.ActivateAsync(analyst, view.RequestId, default);
            return new Suppressed(view.RequestId, sessionId);
        }

        public async Task<SensitiveSessionState> RequestStateAsync(Guid requestId)
        {
            using var scope = Scopes.CreateScope();
            var request = await scope.ServiceProvider.GetRequiredService<ISensitiveSessionRepository>()
                .FindAsync(requestId, default);
            return request!.State;
        }

        public async Task<SessionState> SessionStateAsync(Guid sessionId)
        {
            using var scope = Scopes.CreateScope();
            var session = await scope.ServiceProvider.GetRequiredService<ISessionRepository>()
                .FindAsync(sessionId, default);
            return session!.State;
        }

        public async Task<IReadOnlyList<Guid>> DueAsync()
        {
            using var scope = Scopes.CreateScope();
            return await scope.ServiceProvider.GetRequiredService<SensitiveSessionService>()
                .ListDueForExpiryAsync(default);
        }

        /// <summary>Closing the only connection destroys an in-memory SQLite database.</summary>
        public void BreakTheDatabase() => _connection.Close();

        public void Dispose()
        {
            _provider.Dispose();
            _connection.Dispose();
        }
    }

    private sealed class FakeClock(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset _now = now;

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan by) => _now += by;
    }

    /// <summary>
    /// Fails the expiry event for chosen requests. Audit precedes the state change, so a sink that
    /// throws is exactly the case where the request must be left untouched rather than half-expired.
    /// </summary>
    private sealed class FailableAuditSink : ISensitiveSessionAuditSink
    {
        private readonly HashSet<Guid> _failing = [];

        public void FailFor(Guid requestId) => _failing.Add(requestId);

        public Task ExpiredAsync(
            SensitiveSessionRequest request, bool sessionTerminated, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(request);
            return _failing.Contains(request.Id)
                ? throw new InvalidOperationException("audit write rejected")
                : Task.CompletedTask;
        }

        public Task RequestedAsync(SensitiveSessionRequest request, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task ApprovedAsync(SensitiveSessionRequest request, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task DeniedAsync(SensitiveSessionRequest request, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task CancelledAsync(SensitiveSessionRequest request, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task ActivatedAsync(SensitiveSessionRequest request, CancellationToken cancellationToken) =>
            Task.CompletedTask;
    }
}
