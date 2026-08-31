using Mina.ControlPlane.Application.SensitiveSessions;
using Mina.ControlPlane.Domain.SensitiveSessions;

namespace Mina.ControlPlane.Api.Infrastructure;

/// <summary>
/// Writes the suppression governance trail as structured log events (EVENT_SCHEMAS §3
/// sensitive_*). The durable store and Wazuh delivery replace this in M3-3/M3-5. It records the
/// justification *reference* only — never justification content (threat N4) — and no URL data.
/// </summary>
public sealed partial class LoggingSensitiveSessionAuditSink(ILogger<LoggingSensitiveSessionAuditSink> logger)
    : ISensitiveSessionAuditSink
{
    public Task RequestedAsync(SensitiveSessionRequest request, CancellationToken cancellationToken)
    {
        Log.Requested(logger, request.Id, request.SessionId, request.RequesterUpn,
            request.JustificationReference, (int)request.RequestedDuration.TotalMinutes);
        return Task.CompletedTask;
    }

    public Task ApprovedAsync(SensitiveSessionRequest request, CancellationToken cancellationToken)
    {
        Log.Approved(logger, request.Id, request.ApproverUpn!, request.ExpiresAt!.Value);
        return Task.CompletedTask;
    }

    public Task DeniedAsync(SensitiveSessionRequest request, CancellationToken cancellationToken)
    {
        Log.Denied(logger, request.Id, request.ApproverUpn!);
        return Task.CompletedTask;
    }

    public Task CancelledAsync(SensitiveSessionRequest request, CancellationToken cancellationToken)
    {
        Log.Cancelled(logger, request.Id);
        return Task.CompletedTask;
    }

    public Task ActivatedAsync(SensitiveSessionRequest request, CancellationToken cancellationToken)
    {
        Log.Activated(logger, request.Id, request.SessionId, request.ExpiresAt!.Value);
        return Task.CompletedTask;
    }

    public Task ExpiredAsync(
        SensitiveSessionRequest request, bool sessionTerminated, CancellationToken cancellationToken)
    {
        Log.Expired(logger, request.Id, request.SessionId, sessionTerminated);
        return Task.CompletedTask;
    }

    private static partial class Log
    {
        [LoggerMessage(Level = LogLevel.Information,
            Message = "sensitive_requested id={RequestId} session={SessionId} requester={RequesterUpn} " +
                      "justification_ref={JustificationReference} minutes={RequestedMinutes}")]
        public static partial void Requested(
            ILogger logger, Guid requestId, Guid sessionId, string requesterUpn,
            string justificationReference, int requestedMinutes);

        [LoggerMessage(Level = LogLevel.Information,
            Message = "sensitive_approved id={RequestId} approver={ApproverUpn} expires={ExpiresAt:o}")]
        public static partial void Approved(ILogger logger, Guid requestId, string approverUpn, DateTimeOffset expiresAt);

        [LoggerMessage(Level = LogLevel.Information, Message = "sensitive_denied id={RequestId} approver={ApproverUpn}")]
        public static partial void Denied(ILogger logger, Guid requestId, string approverUpn);

        [LoggerMessage(Level = LogLevel.Information, Message = "sensitive_cancelled id={RequestId}")]
        public static partial void Cancelled(ILogger logger, Guid requestId);

        [LoggerMessage(Level = LogLevel.Information,
            Message = "sensitive_activated id={RequestId} session={SessionId} expires={ExpiresAt:o}")]
        public static partial void Activated(ILogger logger, Guid requestId, Guid sessionId, DateTimeOffset expiresAt);

        [LoggerMessage(Level = LogLevel.Information,
            Message = "sensitive_expired id={RequestId} session={SessionId} session_terminated={SessionTerminated}")]
        public static partial void Expired(ILogger logger, Guid requestId, Guid sessionId, bool sessionTerminated);
    }
}
