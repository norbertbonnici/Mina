using System.Security.Claims;
using Mina.ControlPlane.Application.Sessions;
using Mina.ControlPlane.Application.Telemetry;
using Mina.ControlPlane.Domain.Sessions;

using Mina.ControlPlane.Hosting;

namespace Mina.ControlPlane.Api.Sessions;

public sealed record HostnameConnectionDto(
    DateTimeOffset OccurredAt, string Hostname, int Port, long BytesUp, long BytesDown, int DurationMs, bool IsOffHours);

public sealed record SuppressedIntervalDto(DateTimeOffset IntervalStart, int ConnectionCount, long BytesTotal, bool IsOffHours);

public sealed record SessionBrowsingDto(
    Guid SessionId,
    string UserPrincipalName,
    string? DeviceId,
    string Region,
    string Mode,
    DateTimeOffset CreatedAt,
    DateTimeOffset? EndedAt,
    IReadOnlyList<HostnameConnectionDto> Hostnames,
    IReadOnlyList<SuppressedIntervalDto> SuppressedIntervals);

public sealed record BrowsingDataResultDto(
    IReadOnlyList<SessionBrowsingDto> Sessions, int ConnectionsTotal, int OffHoursFlaggedCount, int SensitiveSessionCount);

public sealed record AnalystSummaryDto(string UserObjectId, string UserPrincipalName, DateTimeOffset LastSessionCreatedAt);

/// <summary>
/// The browsing-data review view's read API (M3-8, FR-013, threat N10). Exists alongside the
/// management UI's own in-process call to <see cref="BrowsingDataReviewService"/> — both routes
/// resolve the same viewer identity from the token and call the same service, so a request that
/// arrives here is authorised and audited exactly as one made from the screen itself, the same
/// property <c>AuditEndpoints</c> already relies on for the governance trail.
/// </summary>
public static class BrowsingDataEndpoints
{
    public const string TelemetryViewerPolicy = "MinaTelemetryViewer";

    public static IEndpointRouteBuilder MapMinaBrowsingDataEndpoints(
        this IEndpointRouteBuilder app, MinaListener listener)
    {
        var group = app.MapGroup("/api/browsing-data")
            .RequireAuthorization(TelemetryViewerPolicy)
            .RequireListener(listener);

        group.MapGet("/", ReviewAsync);
        group.MapGet("/analysts", ListAnalystsAsync);

        return app;
    }

    private static async Task<IResult> ReviewAsync(
        ClaimsPrincipal user,
        BrowsingDataReviewService service,
        string? analyst,
        DateTimeOffset from,
        DateTimeOffset to,
        bool? offHoursOnly,
        CancellationToken cancellationToken)
    {
        try
        {
            var result = await service.ReviewAsync(
                user.ToSessionPrincipal(),
                new BrowsingDataQuery(analyst, from, to, offHoursOnly ?? false),
                cancellationToken).ConfigureAwait(false);
            return Results.Ok(ToDto(result));
        }
        catch (BrowsingDataQueryException ex)
        {
            // Malformed request shape (backwards range, an unscoped query too wide) — the caller's
            // input, not a platform failure, so 400 rather than an unhandled exception.
            return Results.Problem(ex.Message, statusCode: StatusCodes.Status400BadRequest);
        }
    }

    private static async Task<IResult> ListAnalystsAsync(ISessionQueries sessions, CancellationToken cancellationToken)
    {
        var analysts = await sessions.ListDistinctAnalystsAsync(cancellationToken).ConfigureAwait(false);
        return Results.Ok(analysts.Select(
            a => new AnalystSummaryDto(a.UserObjectId, a.UserPrincipalName, a.LastSessionCreatedAt)));
    }

    private static BrowsingDataResultDto ToDto(BrowsingDataResult result) => new(
        [.. result.Sessions.Select(ToDto)],
        result.ConnectionsTotal,
        result.OffHoursFlaggedCount,
        result.SensitiveSessionCount);

    private static SessionBrowsingDto ToDto(SessionBrowsingView view) => new(
        view.SessionId,
        view.UserPrincipalName,
        view.DeviceId,
        view.Region,
        view.Mode.ToString(),
        view.CreatedAt,
        view.EndedAt,
        [.. view.Hostnames.Select(h =>
            new HostnameConnectionDto(h.OccurredAt, h.Hostname, h.Port, h.BytesUp, h.BytesDown, h.DurationMs, h.IsOffHours))],
        [.. view.SuppressedIntervals.Select(s =>
            new SuppressedIntervalDto(s.IntervalStart, s.ConnectionCount, s.BytesTotal, s.IsOffHours))]);
}
