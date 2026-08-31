using Mina.ControlPlane.Application.Sessions;
using Mina.ControlPlane.Domain.Sessions;

namespace Mina.ControlPlane.Api.Infrastructure;

/// <summary>
/// M2-2 audit sink that writes structured log events. The durable audit store (Azure SQL + WORM
/// export) and the Wazuh delivery path (ADR-0005, EVENT_SCHEMAS §3) replace this in M3. It never
/// logs URL/hostname content — only governance facts (LOGGING_AND_PRIVACY: Wazuh gets no browsing
/// content).
/// </summary>
public sealed partial class LoggingSessionAuditSink(ILogger<LoggingSessionAuditSink> logger) : ISessionAuditSink
{
    public Task SessionStartedAsync(ResearchSession session, CancellationToken cancellationToken)
    {
        Log.SessionStarted(logger, session.Id, session.UserObjectId, session.Region, session.Mode);
        return Task.CompletedTask;
    }

    public Task SessionRenewedAsync(ResearchSession session, CancellationToken cancellationToken)
    {
        Log.SessionRenewed(logger, session.Id, session.CertificateSerialNumber);
        return Task.CompletedTask;
    }

    public Task SessionEndedAsync(ResearchSession session, CancellationToken cancellationToken)
    {
        Log.SessionEnded(logger, session.Id, session.State);
        return Task.CompletedTask;
    }

    public Task AuthorizationDeniedAsync(
        SessionPrincipal principal, SessionDenialReason reason, string? region, CancellationToken cancellationToken)
    {
        Log.AuthorizationDenied(logger, principal.UserObjectId, reason, region ?? "-");
        return Task.CompletedTask;
    }

    private static partial class Log
    {
        [LoggerMessage(Level = LogLevel.Information,
            Message = "session_started id={SessionId} oid={UserObjectId} region={Region} mode={Mode}")]
        public static partial void SessionStarted(
            ILogger logger, Guid sessionId, string userObjectId, string region, SessionMode mode);

        [LoggerMessage(Level = LogLevel.Information, Message = "session_renewed id={SessionId} cert={CertSerial}")]
        public static partial void SessionRenewed(ILogger logger, Guid sessionId, string certSerial);

        [LoggerMessage(Level = LogLevel.Information, Message = "session_ended id={SessionId} state={State}")]
        public static partial void SessionEnded(ILogger logger, Guid sessionId, SessionState state);

        [LoggerMessage(Level = LogLevel.Warning,
            Message = "authz_denied oid={UserObjectId} reason={Reason} region={Region}")]
        public static partial void AuthorizationDenied(
            ILogger logger, string userObjectId, SessionDenialReason reason, string region);
    }
}
