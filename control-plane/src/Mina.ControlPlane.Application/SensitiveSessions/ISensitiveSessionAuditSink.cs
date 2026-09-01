using Mina.ControlPlane.Domain.SensitiveSessions;

namespace Mina.ControlPlane.Application.SensitiveSessions;

/// <summary>
/// Sink for the suppression governance trail (EVENT_SCHEMAS §3). These events are mandatory and
/// survive suppression: even while URL telemetry is suppressed, who asked, who approved, and until
/// when are always recorded (ADR-0003). There are no permanent logging exemptions.
/// </summary>
public interface ISensitiveSessionAuditSink
{
    Task RequestedAsync(SensitiveSessionRequest request, CancellationToken cancellationToken);

    Task ApprovedAsync(SensitiveSessionRequest request, CancellationToken cancellationToken);

    Task DeniedAsync(SensitiveSessionRequest request, CancellationToken cancellationToken);

    Task CancelledAsync(SensitiveSessionRequest request, CancellationToken cancellationToken);

    Task ActivatedAsync(SensitiveSessionRequest request, CancellationToken cancellationToken);

    Task ExpiredAsync(SensitiveSessionRequest request, bool sessionTerminated, CancellationToken cancellationToken);

    /// <summary>
    /// Someone who is not the requester tried to act on an existing request. Recorded for the same
    /// reason the session routes record a non-owner attempt: once the API answers a stranger and a
    /// non-existent id identically, the trail is the only place the difference survives, and it is
    /// the half an investigator needs. Only reached for a request that exists — a miss is not
    /// audited, per D-15.
    /// </summary>
    Task RequesterMismatchAsync(
        Guid requestId, string byObjectId, string action, CancellationToken cancellationToken);
}

/// <summary>No-op sink for tests that do not assert on audit.</summary>
public sealed class NullSensitiveSessionAuditSink : ISensitiveSessionAuditSink
{
    public static NullSensitiveSessionAuditSink Instance { get; } = new();

    public Task RequesterMismatchAsync(
        Guid requestId, string byObjectId, string action, CancellationToken cancellationToken) =>
        Task.CompletedTask;

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

    public Task ExpiredAsync(
        SensitiveSessionRequest request, bool sessionTerminated, CancellationToken cancellationToken) =>
        Task.CompletedTask;
}
