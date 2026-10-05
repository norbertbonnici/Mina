using System.Security.Claims;
using Mina.ControlPlane.Application.Audit;
using Mina.ControlPlane.Application.Sessions;
using Mina.ControlPlane.Domain.Audit;
using Mina.ControlPlane.Hosting;

namespace Mina.ControlPlane.Api.Sessions;

/// <summary>One tamper indicator the endpoint agent detected about its own environment.</summary>
public sealed record TamperReportDto(string Indicator, Guid? SessionId);

/// <summary>
/// Accepts tamper indicators the endpoint agent's own self-monitoring detected (ARCHITECTURE
/// §3.1 point 5) — a missing WFP rule, a foreign process on the loopback proxy, and so on — and
/// records each as a `client_tamper_suspected` audit event (EVENT_SCHEMAS §3). Authenticated
/// exactly like session issuance: the same analyst-role Entra token, on the same corporate-facing
/// listener, since this is the agent reporting about itself rather than a node reporting about a
/// session.
/// </summary>
public static class TamperEndpoints
{
    /// <summary>
    /// The only indicator values EVENT_SCHEMAS.md defines. Anything else is refused rather than
    /// recorded, so the audit trail's `indicator` field stays a closed, meaningful set instead of
    /// whatever string a client happened to send.
    /// </summary>
    private static readonly HashSet<string> KnownIndicators = new(StringComparer.Ordinal)
    {
        "wfp_rule_missing",
        "unmanaged_browser_instance",
        "foreign_proxy_client",
        "flag_mismatch",
    };

    public static IEndpointRouteBuilder MapMinaTamperEndpoints(this IEndpointRouteBuilder app, MinaListener listener)
    {
        app.MapPost("/api/agent/tamper-events", ReportAsync)
            .RequireAuthorization(SessionEndpoints.AnalystPolicy)
            .RequireListener(listener);

        return app;
    }

    private static async Task<IResult> ReportAsync(
        TamperReportDto dto, ClaimsPrincipal user, AuditWriter audit, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(dto.Indicator) || !KnownIndicators.Contains(dto.Indicator))
        {
            return Results.Problem("Unknown tamper indicator.", statusCode: StatusCodes.Status400BadRequest);
        }

        var principal = user.ToSessionPrincipal();
        await audit.WriteAsync(
            new AuditEventDraft(
                EventType: "client_tamper_suspected",
                Severity: AuditSeverity.High,
                Component: AuditComponent.EndpointAgent,
                UserObjectId: principal.UserObjectId,
                UserPrincipalName: principal.UserPrincipalName,
                DeviceId: principal.DeviceId,
                SessionId: dto.SessionId,
                Data: new { indicator = dto.Indicator }),
            ct);

        return Results.Accepted();
    }
}
