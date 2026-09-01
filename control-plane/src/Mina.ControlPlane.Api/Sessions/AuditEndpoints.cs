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

/// <summary>
/// The result of verifying the trail. <paramref name="Intact"/> covers the hash chain only —
/// whether the stored events still add up among themselves. The anchor fields are reported
/// separately and deliberately not folded into it: the chain can be perfectly self-consistent and
/// still have been rewritten wholesale, and only the anchors in write-once storage show that.
/// </summary>
public sealed record AuditVerificationDto(
    bool Intact,
    long Verified,
    long? BrokenAtSequence,
    string? Reason,
    int AnchorsChecked,
    int AnchorsMatched,
    IReadOnlyList<string> AnchorProblems);

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

        // Two separate checks. The chain walk finds the first event that does not add up; the
        // anchor check compares the chain against the exports in write-once storage, which is the
        // only part that survives a writer privileged enough to recompute every hash.
        group.MapGet("/verify", async (
            AuditChainVerifier verifier, AuditAnchorVerifier anchors, CancellationToken ct) =>
        {
            var result = await verifier.VerifyAsync(ct);
            var anchored = await anchors.VerifyAsync(ct);
            return Results.Ok(new AuditVerificationDto(
                result.IsIntact, result.Verified, result.BrokenAtSequence, result.Reason,
                anchored.Checked, anchored.Matched, anchored.Problems));
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
