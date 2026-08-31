using Mina.ControlPlane.Application.Audit;
using Mina.ControlPlane.Domain.Audit;

namespace Mina.ControlPlane.Api.Sessions;

public sealed record AuditEventDto(
    long Sequence,
    string EventType,
    string Severity,
    string Component,
    DateTimeOffset OccurredAt,
    string? Region,
    string? UserPrincipalName,
    Guid? SessionId,
    string Data);

public sealed record AuditVerificationDto(bool Intact, long Verified, long? BrokenAtSequence, string? Reason);

/// <summary>
/// Read and verification access to the audit trail, for platform administrators.
/// </summary>
/// <remarks>
/// There is deliberately no write, amend or delete endpoint: the trail is append-only, and events
/// are written by the actions that cause them. Reading it is itself a privileged operation, since
/// the trail names who did what and when.
/// </remarks>
public static class AuditEndpoints
{
    public const string AdminPolicy = "MinaAdmin";

    public static IEndpointRouteBuilder MapMinaAuditEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/audit").RequireAuthorization(AdminPolicy);

        group.MapGet("/recent", async (IAuditEventStore store, int? limit, CancellationToken ct) =>
        {
            var events = await store.ReadRecentAsync(Math.Clamp(limit ?? 100, 1, 500), ct);
            return Results.Ok(events.Select(ToDto));
        });

        // Walks the chain and reports the first event that does not add up. An intact result is
        // evidence the stored trail has not been altered since it was written.
        group.MapGet("/verify", async (AuditChainVerifier verifier, CancellationToken ct) =>
        {
            var result = await verifier.VerifyAsync(ct);
            return Results.Ok(new AuditVerificationDto(
                result.IsIntact, result.Verified, result.BrokenAtSequence, result.Reason));
        });

        return app;
    }

    private static AuditEventDto ToDto(AuditEvent e) => new(
        e.Sequence,
        e.EventType,
        e.Severity.ToString(),
        e.Component.ToString(),
        e.OccurredAt,
        e.Region,
        e.UserPrincipalName,
        e.SessionId,
        e.Data);
}
