using Mina.ControlPlane.Application.Sessions;
using Mina.ControlPlane.Domain.Audit;

namespace Mina.ControlPlane.Application.Audit;

/// <summary>
/// One audit event as shown to a platform administrator. A thin projection of
/// <see cref="AuditEvent"/> rather than the domain type itself, the same reason the API's own
/// <c>AuditEventDto</c> exists separately — a UI-facing shape should not accidentally start
/// depending on the chain's internal fields (<c>PreviousHash</c>, <c>Hash</c>, <c>Id</c>) that have
/// nothing to do with what an administrator is looking for.
/// </summary>
public sealed record AuditEventView(
    long Sequence,
    string EventType,
    AuditSeverity Severity,
    AuditComponent Component,
    DateTimeOffset OccurredAt,
    string? Region,
    string? UserPrincipalName,
    string? DeviceId,
    Guid? SessionId,
    string Data);

/// <summary>
/// A request to browse the recent audit trail. All three filters are optional and applied
/// client-side over the fetched window — <see cref="IAuditEventStore"/> exposes no server-side
/// filter, by design (it is deliberately minimal: append, read-from, read-recent), so narrowing
/// happens after the read rather than by extending the store's own contract for a v1 admin screen.
/// </summary>
public sealed record AuditReviewQuery(
    int Limit = 200,
    AuditSeverity? Severity = null,
    AuditComponent? Component = null,
    string? EventTypeContains = null);

public sealed record AuditReviewResult(IReadOnlyList<AuditEventView> Events, int TotalBeforeFilter);

/// <summary>
/// The read path behind the audit trail screen (M3-2's own "audit views" remaining item, unblocked
/// once M3-3's store existed). Reads the most recent events from <see cref="IAuditEventStore"/> —
/// the read method that store's own doc comment already names "for the management interface" — and
/// writes exactly one <c>audit_trail_viewed</c> event per query, always, the same discipline
/// <see cref="Telemetry.BrowsingDataReviewService"/> applies to <c>telemetry_viewed</c>: reading the
/// audit trail is itself a privileged operation (<c>AuditEndpoints</c>'s own remark), so who looked
/// and when is itself worth recording, not only what a reviewer looked at.
/// </summary>
public sealed class AuditReviewService(IAuditEventStore store, AuditWriter writer)
{
    /// <summary>Hard ceiling regardless of what a caller requests, matching the API's own <c>/api/audit/recent</c> clamp.</summary>
    public const int MaxLimit = 500;

    private readonly IAuditEventStore _store = store ?? throw new ArgumentNullException(nameof(store));
    private readonly AuditWriter _writer = writer ?? throw new ArgumentNullException(nameof(writer));

    public async Task<AuditReviewResult> ReviewAsync(
        SessionPrincipal viewer, AuditReviewQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(viewer);
        ArgumentNullException.ThrowIfNull(query);

        var limit = Math.Clamp(query.Limit, 1, MaxLimit);
        var events = await _store.ReadRecentAsync(limit, cancellationToken).ConfigureAwait(false);

        IEnumerable<AuditEvent> filtered = events;
        if (query.Severity is not null)
        {
            filtered = filtered.Where(e => e.Severity == query.Severity.Value);
        }

        if (query.Component is not null)
        {
            filtered = filtered.Where(e => e.Component == query.Component.Value);
        }

        if (!string.IsNullOrWhiteSpace(query.EventTypeContains))
        {
            filtered = filtered.Where(e =>
                e.EventType.Contains(query.EventTypeContains, StringComparison.OrdinalIgnoreCase));
        }

        var views = filtered.Select(ToView).ToList();

        // Written unconditionally, after the read completes and before returning it — the same
        // "the service writes it, not whichever caller invoked the service" placement
        // BrowsingDataReviewService uses, so there is exactly one place this access is audited from.
        await _writer.WriteAsync(new AuditEventDraft(
            "audit_trail_viewed",
            AuditSeverity.Notice,
            AuditComponent.ManagementUi,
            UserObjectId: viewer.UserObjectId,
            UserPrincipalName: viewer.UserPrincipalName,
            Data: new
            {
                events_returned = views.Count,
                events_before_filter = events.Count,
                severity_filter = query.Severity?.ToString(),
                component_filter = query.Component?.ToString(),
            }), cancellationToken).ConfigureAwait(false);

        return new AuditReviewResult(views, events.Count);
    }

    private static AuditEventView ToView(AuditEvent e) => new(
        e.Sequence, e.EventType, e.Severity, e.Component, e.OccurredAt,
        e.Region, e.UserPrincipalName, e.DeviceId, e.SessionId, e.Data);
}
