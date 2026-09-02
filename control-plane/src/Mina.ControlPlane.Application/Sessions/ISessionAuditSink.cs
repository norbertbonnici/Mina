using Mina.ControlPlane.Domain.Sessions;

namespace Mina.ControlPlane.Application.Sessions;

/// <summary>
/// Sink for session governance events. The M2-2 wiring records them; the Wazuh delivery path
/// (ADR-0005) and the full event envelope (EVENT_SCHEMAS §2) are added in M3-5. Audit writes are
/// on the critical path — a session operation that cannot be recorded must not silently proceed.
/// </summary>
public interface ISessionAuditSink
{
    Task SessionStartedAsync(ResearchSession session, CancellationToken cancellationToken);

    Task SessionRenewedAsync(ResearchSession session, CancellationToken cancellationToken);

    Task SessionEndedAsync(ResearchSession session, CancellationToken cancellationToken);

    Task AuthorizationDeniedAsync(
        SessionPrincipal principal, SessionDenialReason reason, string? region, CancellationToken cancellationToken);
}

/// <summary>No-op sink for local runs and tests that do not assert on audit.</summary>
public sealed class NullSessionAuditSink : ISessionAuditSink
{
    public static NullSessionAuditSink Instance { get; } = new();

    public Task SessionStartedAsync(ResearchSession session, CancellationToken cancellationToken) => Task.CompletedTask;

    public Task SessionRenewedAsync(ResearchSession session, CancellationToken cancellationToken) => Task.CompletedTask;

    public Task SessionEndedAsync(ResearchSession session, CancellationToken cancellationToken) => Task.CompletedTask;

    public Task AuthorizationDeniedAsync(
        SessionPrincipal principal, SessionDenialReason reason, string? region, CancellationToken cancellationToken)
        => Task.CompletedTask;
}
