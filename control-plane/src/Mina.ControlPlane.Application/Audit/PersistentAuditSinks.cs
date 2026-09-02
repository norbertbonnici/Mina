using Mina.ControlPlane.Application.SensitiveSessions;
using Mina.ControlPlane.Application.Sessions;
using Mina.ControlPlane.Application.Telemetry;
using Mina.ControlPlane.Domain.Audit;
using Mina.ControlPlane.Domain.SensitiveSessions;
using Mina.ControlPlane.Domain.Sessions;

namespace Mina.ControlPlane.Application.Audit;

/// <summary>
/// Session lifecycle events, written to the durable chain (EVENT_SCHEMAS §3).
/// </summary>
public sealed class PersistentSessionAuditSink(AuditWriter writer) : ISessionAuditSink
{
    private readonly AuditWriter _writer = writer ?? throw new ArgumentNullException(nameof(writer));

    public Task SessionStartedAsync(ResearchSession session, CancellationToken cancellationToken) =>
        _writer.WriteAsync(Draft(session, "session_started", AuditSeverity.Info, new
        {
            region = session.Region,
            mode = session.Mode.ToString(),
            certificate_serial = session.CertificateSerialNumber,
            lease_expires_at = session.LeaseExpiresAt,
        }), cancellationToken);

    public Task SessionRenewedAsync(ResearchSession session, CancellationToken cancellationToken) =>
        _writer.WriteAsync(Draft(session, "session_renewed", AuditSeverity.Info, new
        {
            certificate_serial = session.CertificateSerialNumber,
            lease_expires_at = session.LeaseExpiresAt,
        }), cancellationToken);

    public Task SessionEndedAsync(ResearchSession session, CancellationToken cancellationToken) =>
        _writer.WriteAsync(Draft(
            session,
            EventTypeFor(session.State),
            session.State == SessionState.Revoked ? AuditSeverity.High : AuditSeverity.Info,
            new { state = session.State.ToString(), reason = session.EndReason?.ToString(), revoked_by = session.RevokedBy }),
            cancellationToken);

    /// <summary>
    /// A session's terminal event, named for how it ended. `session_expired` was catalogued in
    /// EVENT_SCHEMAS but emitted by nothing, because nothing swept lapsed leases; it now has a
    /// producer.
    /// </summary>
    private static string EventTypeFor(SessionState state) => state switch
    {
        SessionState.Revoked => "session_revoked",
        SessionState.Expired => "session_expired",
        _ => "session_ended",
    };

    public Task AuthorizationDeniedAsync(
        SessionPrincipal principal, SessionDenialReason reason, string? region, CancellationToken cancellationToken) =>
        _writer.WriteAsync(new AuditEventDraft(
            "authz_denied",
            AuditSeverity.Warning,
            AuditComponent.ControlPlane,
            Region: region,
            UserObjectId: principal.UserObjectId,
            UserPrincipalName: principal.UserPrincipalName,
            DeviceId: principal.DeviceId,
            Data: new { reason = reason.ToString() }), cancellationToken);

    private static AuditEventDraft Draft(
        ResearchSession session, string eventType, AuditSeverity severity, object data) =>
        new(eventType,
            severity,
            AuditComponent.ControlPlane,
            Region: session.Region,
            UserObjectId: session.UserObjectId,
            UserPrincipalName: session.UserPrincipalName,
            DeviceId: session.DeviceId,
            SessionId: session.Id,
            Data: data);
}

/// <summary>
/// The suppression governance trail. These events are mandatory and survive suppression itself:
/// who asked, under what reference, who decided and until when are recorded even while URL
/// telemetry is being withheld (ADR-0003). The justification *reference* is recorded, never
/// justification content (threat N4).
/// </summary>
public sealed class PersistentSensitiveSessionAuditSink(AuditWriter writer) : ISensitiveSessionAuditSink
{
    private readonly AuditWriter _writer = writer ?? throw new ArgumentNullException(nameof(writer));

    public Task RequesterMismatchAsync(
        Guid requestId, string byObjectId, string action, CancellationToken cancellationToken) =>
        _writer.WriteAsync(
            new AuditEventDraft(
                "authz_denied",
                AuditSeverity.Warning,
                AuditComponent.ControlPlane,
                UserObjectId: byObjectId,
                Data: new { reason = "NotRequester", request_id = requestId, action }),
            cancellationToken);

    public Task RequestedAsync(SensitiveSessionRequest request, CancellationToken cancellationToken) =>
        Write(request, "sensitive_requested", AuditSeverity.Notice, new
        {
            request_id = request.Id,
            justification_ref = request.JustificationReference,
            requested_minutes = (int)request.RequestedDuration.TotalMinutes,
        }, cancellationToken);

    public Task ApprovedAsync(SensitiveSessionRequest request, CancellationToken cancellationToken) =>
        Write(request, "sensitive_approved", AuditSeverity.Notice, new
        {
            request_id = request.Id,
            approver_upn = request.ApproverUpn,
            approver_oid = request.ApproverObjectId,
            expires_at = request.ExpiresAt,
        }, cancellationToken);

    public Task DeniedAsync(SensitiveSessionRequest request, CancellationToken cancellationToken) =>
        Write(request, "sensitive_denied", AuditSeverity.Notice,
            new { request_id = request.Id, approver_upn = request.ApproverUpn }, cancellationToken);

    public Task CancelledAsync(SensitiveSessionRequest request, CancellationToken cancellationToken) =>
        Write(request, "sensitive_cancelled", AuditSeverity.Notice,
            new { request_id = request.Id }, cancellationToken);

    public Task ActivatedAsync(SensitiveSessionRequest request, CancellationToken cancellationToken) =>
        Write(request, "sensitive_activated", AuditSeverity.Notice,
            new { request_id = request.Id, expires_at = request.ExpiresAt }, cancellationToken);

    public Task ExpiredAsync(
        SensitiveSessionRequest request, bool sessionTerminated, CancellationToken cancellationToken) =>
        Write(request, "sensitive_expired", AuditSeverity.Notice,
            new { request_id = request.Id, session_terminated = sessionTerminated }, cancellationToken);

    private Task<AuditEvent> Write(
        SensitiveSessionRequest request, string eventType, AuditSeverity severity, object data,
        CancellationToken cancellationToken) =>
        _writer.WriteAsync(new AuditEventDraft(
            eventType,
            severity,
            AuditComponent.ControlPlane,
            UserObjectId: request.RequesterObjectId,
            UserPrincipalName: request.RequesterUpn,
            SessionId: request.SessionId,
            Data: data), cancellationToken);
}

/// <summary>
/// Telemetry security events. A suppression mismatch is critical: a node was still collecting
/// destinations for a session an approver had suppressed (threat N5). No hostname is ever placed in
/// an audit event — the audit trail records that it happened, not what was reached.
/// </summary>
public sealed class PersistentTelemetryAuditSink(AuditWriter writer) : ITelemetryAuditSink
{
    private readonly AuditWriter _writer = writer ?? throw new ArgumentNullException(nameof(writer));

    public Task SuppressionMismatchAsync(
        Guid sessionId, string region, int itemCount, CancellationToken cancellationToken) =>
        _writer.WriteAsync(new AuditEventDraft(
            "sensitive_suppression_mismatch",
            AuditSeverity.Critical,
            AuditComponent.EgressNode,
            Region: region,
            SessionId: sessionId,
            Data: new { discarded_items = itemCount }), cancellationToken);

    public Task RegionMismatchAsync(
        Guid sessionId, string claimedRegion, string sessionRegion, int itemCount,
        CancellationToken cancellationToken) =>
        _writer.WriteAsync(new AuditEventDraft(
            "telemetry_region_mismatch",
            AuditSeverity.High,
            AuditComponent.EgressNode,
            Region: claimedRegion,
            SessionId: sessionId,
            Data: new { claimed_region = claimedRegion, session_region = sessionRegion, discarded_items = itemCount }),
            cancellationToken);

    public Task UnattributableTelemetryAsync(
        Guid sessionId, string region, int itemCount, CancellationToken cancellationToken) =>
        _writer.WriteAsync(new AuditEventDraft(
            "telemetry_unattributable",
            AuditSeverity.Warning,
            AuditComponent.EgressNode,
            Region: region,
            SessionId: sessionId,
            Data: new { discarded_items = itemCount }), cancellationToken);

    public Task RetentionAppliedAsync(
        DateTimeOffset cutoff, int hostnames, int suppressedSummaries, CancellationToken cancellationToken) =>
        _writer.WriteAsync(new AuditEventDraft(
            "telemetry_retention_applied",
            AuditSeverity.Info,
            AuditComponent.ControlPlane,
            Data: new
            {
                data_class = "C3",
                cutoff = cutoff.ToString("O", System.Globalization.CultureInfo.InvariantCulture),
                hostnames_deleted = hostnames,
                suppressed_summaries_deleted = suppressedSummaries,
            }), cancellationToken);
}
