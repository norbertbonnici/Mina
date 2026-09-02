using System.Security.Claims;
using Mina.ControlPlane.Application.SensitiveSessions;
using Mina.ControlPlane.Application.Sessions;
using Mina.ControlPlane.Domain.SensitiveSessions;

using Mina.ControlPlane.Hosting;

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
/// <summary>The approver queue as returned to a client, with whether it was truncated.</summary>
public sealed record PendingApprovalsDto(
    IReadOnlyList<SensitiveSessionDto> Requests, bool HasMore, int Offset);

public static class SensitiveSessionEndpoints
{
    public const string ApproverPolicy = "MinaApprover";

    public static IEndpointRouteBuilder MapMinaSensitiveSessionEndpoints(
        this IEndpointRouteBuilder app, MinaListener listener)
    {
        // Raised against a session the analyst owns.
        app.MapPost("/api/sessions/{sessionId:guid}/sensitive", RequestAsync)
            .RequireAuthorization(SessionEndpoints.AnalystPolicy)
            .RequireListener(listener);

        var group = app.MapGroup("/api/sensitive-requests").RequireAuthorization()
            .RequireListener(listener);

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
        ClaimsPrincipal user, SensitiveSessionService service, int? offset, CancellationToken ct) =>
        ExecuteAsync(async () =>
        {
            var pending = await service.ListPendingAsync(
                user.ToSessionPrincipal(), ct, Math.Max(0, offset ?? 0));

            // hasMore, not a bare array: a client that cannot tell a full queue from a truncated
            // one will present a partial queue as the whole of it.
            return Results.Ok(new PendingApprovalsDto(
                [.. pending.Requests.Select(ToDto)], pending.HasMore, pending.Offset));
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
                // NotRequester joins the not-found arm for the same reason as NotSessionOwner on
                // the session routes: a request id that exists but belongs to someone else must not
                // be distinguishable from one that does not exist.
                SensitiveSessionDenialReason.RequestNotFound
                    or SensitiveSessionDenialReason.SessionNotFound
                    or SensitiveSessionDenialReason.NotRequester =>
                    Results.NotFound(),
                _ => Results.Problem($"Denied: {ex.Reason}", statusCode: StatusCodes.Status403Forbidden),
            };
        }
        catch (SensitiveSessionRuleViolationException ex)
        {
            return ex.Rule switch
            {
                // The session already has a request awaiting a decision. The caller's situation,
                // not a malformed request: 409 tells them to wait for or withdraw the existing one.
                SensitiveSessionRule.RequestAlreadyPending =>
                    Results.Problem(ex.Message, statusCode: StatusCodes.Status409Conflict),

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
