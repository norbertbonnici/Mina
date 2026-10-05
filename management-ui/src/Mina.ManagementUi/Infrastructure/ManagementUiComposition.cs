using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Mina.ControlPlane.Application.Regions;
using Mina.ControlPlane.Application.SensitiveSessions;
using Mina.ControlPlane.Domain.Regions;
using Mina.ControlPlane.Domain.SensitiveSessions;
using Mina.ManagementUi.Components;

namespace Mina.ManagementUi.Infrastructure;

/// <summary>
/// The management UI's composition, shared by its own host and by the demo harness so both run the
/// same screens, policies and decision endpoints rather than a re-implementation.
/// </summary>
public static class ManagementUiComposition
{
    /// <summary>Screens, authorization policies and the request-scoped identity accessor.</summary>
    public static IServiceCollection AddManagementUi(
        this IServiceCollection services, string approverRole, string adminRole, string telemetryViewerRole)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddRazorComponents();
        services.AddCascadingAuthenticationState();
        services.AddHttpContextAccessor();
        services.AddScoped<ClaimsPrincipalAccessor>();

        services.AddAuthorizationBuilder()
            .AddPolicy(UiPolicies.Approver, policy => policy.RequireRole(approverRole))
            .AddPolicy(UiPolicies.Admin, policy => policy.RequireRole(adminRole))
            .AddPolicy(UiPolicies.TelemetryViewer, policy => policy.RequireRole(telemetryViewerRole))
            .SetFallbackPolicy(new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build());

        return services;
    }

    /// <summary>Maps the screens and the approve/deny form posts.</summary>
    public static WebApplication MapManagementUi(this WebApplication app)
    {
        ArgumentNullException.ThrowIfNull(app);

        app.MapRazorComponents<App>();

        // Plain form posts keep the screens free of client-side state; antiforgery is validated
        // automatically for [FromForm] parameters because UseAntiforgery is configured.
        app.MapPost("/approvals/approve", async (
                [FromForm] Guid requestId,
                [FromForm] int ttlMinutes,
                ClaimsPrincipalAccessor accessor,
                SensitiveSessionService service,
                CancellationToken ct) =>
            await DecideAsync(
                () => service.ApproveAsync(accessor.Principal, requestId, TimeSpan.FromMinutes(ttlMinutes), ct),
                "Approved."))
            .RequireAuthorization(UiPolicies.Approver);

        app.MapPost("/approvals/deny", async (
                [FromForm] Guid requestId,
                ClaimsPrincipalAccessor accessor,
                SensitiveSessionService service,
                CancellationToken ct) =>
            await DecideAsync(() => service.DenyAsync(accessor.Principal, requestId, ct), "Denied."))
            .RequireAuthorization(UiPolicies.Approver);

        // Region change requests (ADR-0008 Option C). Same plain-form-post shape as approvals above;
        // "apply" and "dismiss" resolve a request, they never touch Mina:Regions:Approved/Active
        // themselves -- see RegionChangeRequestService's own remarks for why.
        app.MapPost("/region-requests/create", async (
                [FromForm] RegionChangeKind kind,
                [FromForm] string regionName,
                [FromForm] string justification,
                ClaimsPrincipalAccessor accessor,
                RegionChangeRequestService service,
                CancellationToken ct) =>
            await DecideRegionRequestAsync(
                () => service.RequestAsync(accessor.Principal, kind, regionName, justification, ct),
                "Request submitted."))
            .RequireAuthorization(UiPolicies.Admin);

        app.MapPost("/region-requests/apply", async (
                [FromForm] Guid requestId,
                [FromForm] string? note,
                ClaimsPrincipalAccessor accessor,
                RegionChangeRequestService service,
                CancellationToken ct) =>
            await DecideRegionRequestAsync(
                () => service.MarkAppliedAsync(accessor.Principal, requestId, note, ct), "Marked applied."))
            .RequireAuthorization(UiPolicies.Admin);

        app.MapPost("/region-requests/dismiss", async (
                [FromForm] Guid requestId,
                [FromForm] string reason,
                ClaimsPrincipalAccessor accessor,
                RegionChangeRequestService service,
                CancellationToken ct) =>
            await DecideRegionRequestAsync(
                () => service.DismissAsync(accessor.Principal, requestId, reason, ct), "Dismissed."))
            .RequireAuthorization(UiPolicies.Admin);

        return app;
    }

    /// <summary>
    /// Runs one decision and redirects back to the queue. Refusals are shown to the approver rather
    /// than swallowed: a rejected self-approval is information, not an error page.
    /// </summary>
    private static async Task<IResult> DecideAsync(Func<Task<SensitiveSessionView>> decide, string success)
    {
        try
        {
            await decide();
            return Results.Redirect($"/approvals?done={Uri.EscapeDataString(success)}");
        }
        catch (Exception ex)
            when (ex is SensitiveSessionRuleViolationException or SensitiveSessionAuthorizationException)
        {
            return Results.Redirect($"/approvals?error={Uri.EscapeDataString(ex.Message)}");
        }
    }

    /// <summary>Same shape as <see cref="DecideAsync"/>, for the region-request screen's own
    /// exception types.</summary>
    private static async Task<IResult> DecideRegionRequestAsync(
        Func<Task<RegionChangeRequestView>> decide, string success)
    {
        try
        {
            await decide();
            return Results.Redirect($"/region-requests?done={Uri.EscapeDataString(success)}");
        }
        catch (Exception ex)
            when (ex is RegionChangeRuleViolationException or RegionChangeRequestAuthorizationException
                or RegionChangeRequestNotFoundException)
        {
            return Results.Redirect($"/region-requests?error={Uri.EscapeDataString(ex.Message)}");
        }
    }
}
