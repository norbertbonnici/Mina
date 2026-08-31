using System.Security.Claims;
using Mina.ControlPlane.Application.SensitiveSessions;
using Mina.ControlPlane.Domain.SensitiveSessions;

namespace Mina.ControlPlane.Api.Sessions;

public sealed record RequestSuppressionDto(string JustificationReference, int RequestedMinutes);

public sealed record ApproveSuppressionDto(int TtlMinutes);

public sealed record SensitiveSessionDto(
    Guid RequestId,
    Guid SessionId,
    string RequesterUpn,
    string JustificationReference,
    int RequestedMinutes,
    DateTimeOffset RequestedAt,
    string State,
    string? ApproverUpn,
    DateTimeOffset? ApprovedAt,
    DateTimeOffset? ExpiresAt,
    DateTimeOffset? ActivatedAt);

/// <summary>
/// The manager-approved suppression workflow (ADR-0003). Requesting and activating need the
/// analyst role; approving and denying need the approver role — and the control plane additionally
/// refuses to let anyone decide their own request, so holding both roles still does not permit
/// self-approval.
/// </summary>
public static class SensitiveSessionEndpoints
{
    public const string ApproverPolicy = "MinaApprover";

    public static IEndpointRouteBuilder MapMinaSensitiveSessionEndpoints(this IEndpointRouteBuilder app)
    {
        // Raised against a session the analyst owns.
        app.MapPost("/api/sessions/{sessionId:guid}/sensitive", RequestAsync)
            .RequireAuthorization(SessionEndpoints.AnalystPolicy);

        var group = app.MapGroup("/api/sensitive-requests").RequireAuthorization();

        group.MapGet("/pending", ListPendingAsync).RequireAuthorization(ApproverPolicy);
        group.MapPost("/{id:guid}/approve", ApproveAsync).RequireAuthorization(ApproverPolicy);
        group.MapPost("/{id:guid}/deny", DenyAsync).RequireAuthorization(ApproverPolicy);
        group.MapPost("/{id:guid}/activate", ActivateAsync).RequireAuthorization(SessionEndpoints.AnalystPolicy);
        group.MapDelete("/{id:guid}", CancelAsync).RequireAuthorization(SessionEndpoints.AnalystPolicy);
        group.MapGet("/{id:guid}", GetAsync);

        return app;
    }

    private static Task<IResult> RequestAsync(
        Guid sessionId,
        RequestSuppressionDto dto,
        ClaimsPrincipal user,
        SensitiveSessionService service,
        CancellationToken ct) =>
        ExecuteAsync(async () =>
        {
            var view = await service.RequestAsync(
                user.ToSessionPrincipal(), sessionId, dto.JustificationReference,
                TimeSpan.FromMinutes(dto.RequestedMinutes), ct);
            return Results.Created($"/api/sensitive-requests/{view.RequestId}", ToDto(view));
        });

    private static Task<IResult> ApproveAsync(
        Guid id, ApproveSuppressionDto dto, ClaimsPrincipal user, SensitiveSessionService service, CancellationToken ct) =>
        ExecuteAsync(async () => Results.Ok(ToDto(
            await service.ApproveAsync(user.ToSessionPrincipal(), id, TimeSpan.FromMinutes(dto.TtlMinutes), ct))));

    private static Task<IResult> DenyAsync(
        Guid id, ClaimsPrincipal user, SensitiveSessionService service, CancellationToken ct) =>
        ExecuteAsync(async () => Results.Ok(ToDto(await service.DenyAsync(user.ToSessionPrincipal(), id, ct))));

    private static Task<IResult> ActivateAsync(
        Guid id, ClaimsPrincipal user, SensitiveSessionService service, CancellationToken ct) =>
        ExecuteAsync(async () => Results.Ok(ToDto(await service.ActivateAsync(user.ToSessionPrincipal(), id, ct))));

    private static Task<IResult> CancelAsync(
        Guid id, ClaimsPrincipal user, SensitiveSessionService service, CancellationToken ct) =>
        ExecuteAsync(async () => Results.Ok(ToDto(await service.CancelAsync(user.ToSessionPrincipal(), id, ct))));

    private static Task<IResult> GetAsync(
        Guid id, ClaimsPrincipal user, SensitiveSessionService service, CancellationToken ct) =>
        ExecuteAsync(async () => Results.Ok(ToDto(await service.GetAsync(user.ToSessionPrincipal(), id, ct))));

    private static Task<IResult> ListPendingAsync(
        ClaimsPrincipal user, SensitiveSessionService service, CancellationToken ct) =>
        ExecuteAsync(async () =>
        {
            var pending = await service.ListPendingAsync(user.ToSessionPrincipal(), ct);
            return Results.Ok(pending.Select(ToDto));
        });

    private static async Task<IResult> ExecuteAsync(Func<Task<IResult>> action)
    {
        try
        {
            return await action();
        }
        catch (SensitiveSessionAuthorizationException ex)
        {
            return ex.Reason switch
            {
                SensitiveSessionDenialReason.RequestNotFound or SensitiveSessionDenialReason.SessionNotFound =>
                    Results.NotFound(),
                _ => Results.Problem($"Denied: {ex.Reason}", statusCode: StatusCodes.Status403Forbidden),
            };
        }
        catch (SensitiveSessionRuleViolationException ex)
        {
            return ex.Rule switch
            {
                // Self-approval and acting on someone else's request are authorisation failures.
                SensitiveSessionRule.SelfApprovalForbidden or SensitiveSessionRule.NotRequester =>
                    Results.Problem(ex.Message, statusCode: StatusCodes.Status403Forbidden),

                // The request exists but is not in a state that allows this — a caller-side
                // condition, so 409 rather than an unhandled failure.
                SensitiveSessionRule.InvalidTransition or SensitiveSessionRule.ApprovalWindowElapsed =>
                    Results.Problem(ex.Message, statusCode: StatusCodes.Status409Conflict),

                // Malformed input: missing justification, duration outside policy.
                _ => Results.Problem(ex.Message, statusCode: StatusCodes.Status400BadRequest),
            };
        }
    }

    private static SensitiveSessionDto ToDto(SensitiveSessionView view) => new(
        view.RequestId,
        view.SessionId,
        view.RequesterUpn,
        view.JustificationReference,
        (int)view.RequestedDuration.TotalMinutes,
        view.RequestedAt,
        view.State.ToString(),
        view.ApproverUpn,
        view.ApprovedAt,
        view.ExpiresAt,
        view.ActivatedAt);
}
