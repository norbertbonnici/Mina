using Microsoft.Extensions.Options;
using Mina.ControlPlane.Application.Audit;
using Mina.ControlPlane.Application.Sessions;
using Mina.ControlPlane.Domain.Audit;
using Mina.ControlPlane.Domain.Regions;

namespace Mina.ControlPlane.Application.Regions;

/// <summary>One region change request, as shown to an admin.</summary>
public sealed record RegionChangeRequestView(
    Guid Id,
    string RequestedByUpn,
    RegionChangeKind Kind,
    string RegionName,
    string Justification,
    DateTimeOffset RequestedAt,
    RegionChangeRequestStatus Status,
    string? ResolvedByUpn,
    DateTimeOffset? ResolvedAt,
    string? ResolutionNote)
{
    public static RegionChangeRequestView From(RegionChangeRequest r) => new(
        r.Id, r.RequestedByUpn, r.Kind, r.RegionName, r.Justification, r.RequestedAt, r.Status,
        r.ResolvedByUpn, r.ResolvedAt, r.ResolutionNote);
}

/// <summary>Raised when a request id names nothing this repository holds.</summary>
public sealed class RegionChangeRequestNotFoundException(Guid requestId)
    : Exception($"No region change request with id '{requestId}'.")
{
    public Guid RequestId { get; } = requestId;
}

/// <summary>Raised when the caller does not hold the required role. Checked here too, not only by
/// the HTTP/UI authorization policy — the same defense-in-depth <c>SensitiveSessionService</c>
/// applies, and for the same reason: the policy's role name and this option's are two keys that are
/// equal by default and need not stay equal.</summary>
public sealed class RegionChangeRequestAuthorizationException()
    : Exception("The caller does not hold the role required to manage region change requests.");

public sealed class RegionChangeRequestOptions
{
    public const string Section = "Mina:RegionChangeRequests";

    /// <summary>App role required to request, apply, or dismiss. Region administration is an admin
    /// concern (ADR-0008) — deliberately not split into a separate requester/resolver role the way
    /// sensitive sessions splits analyst/approver, since nothing here requires a second party to
    /// authorize: the reviewed deploy script is what actually changes anything, and the same admin
    /// who asked for a change may well be the one who runs it.</summary>
    public string AdminRole { get; set; } = "Mina.Admin";

    /// <summary>Cap on the pending queue. Not paged like the sensitive-session approver queue —
    /// region changes are rare, deliberate operations (standing up or retiring an egress stamp), not
    /// something an ordinary user can flood, so a single bounded read is proportionate.</summary>
    public int PendingQueueLimit { get; set; } = 100;

    /// <summary>Cap on the "recently resolved" history shown alongside the pending queue.</summary>
    public int RecentHistoryLimit { get; set; } = 50;
}

/// <summary>
/// The region change request workflow (ADR-0008 Option C, backlog M3-2). Captures and audits
/// intent to change the approved/active region list; it never itself changes
/// <c>Mina:Regions:Approved</c>/<c>Active</c> or anything a device reads — that authority stays
/// entirely with the reviewed <c>deploy-control-plane-api-windows.ps1</c>/
/// <c>deploy-management-ui-windows.ps1</c> runs, matching CLAUDE.md's stop condition on changing the
/// approved production region strategy. "Applying" a request here means an admin confirming that
/// deploy already happened, not causing it.
/// </summary>
public sealed class RegionChangeRequestService(
    IRegionChangeRequestRepository requests,
    AuditWriter audit,
    TimeProvider clock,
    IOptions<RegionChangeRequestOptions> options)
{
    private readonly IRegionChangeRequestRepository _requests = requests ?? throw new ArgumentNullException(nameof(requests));
    private readonly AuditWriter _audit = audit ?? throw new ArgumentNullException(nameof(audit));
    private readonly TimeProvider _clock = clock ?? throw new ArgumentNullException(nameof(clock));
    private readonly RegionChangeRequestOptions _options =
        (options ?? throw new ArgumentNullException(nameof(options))).Value;

    public async Task<RegionChangeRequestView> RequestAsync(
        SessionPrincipal principal, RegionChangeKind kind, string regionName, string justification,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);
        RequireRole(principal);

        var request = RegionChangeRequest.Create(
            Guid.NewGuid(), principal.UserObjectId, principal.UserPrincipalName, kind, regionName, justification,
            _clock.GetUtcNow());

        // Audit before the record exists, matching every other governance workflow here: no request
        // can exist unaudited, even this lightweight one.
        await _audit.WriteAsync(new AuditEventDraft(
            "region_change_requested",
            AuditSeverity.Notice,
            AuditComponent.ManagementUi,
            UserObjectId: principal.UserObjectId,
            UserPrincipalName: principal.UserPrincipalName,
            Data: new { kind = request.Kind.ToString(), region = request.RegionName, justification = request.Justification }),
            cancellationToken).ConfigureAwait(false);

        await _requests.AddAsync(request, cancellationToken).ConfigureAwait(false);
        return RegionChangeRequestView.From(request);
    }

    /// <summary>Confirms the request was actually applied through the reviewed deploy path.</summary>
    public async Task<RegionChangeRequestView> MarkAppliedAsync(
        SessionPrincipal principal, Guid requestId, string? note, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);
        RequireRole(principal);

        var request = await RequireRequestAsync(requestId, cancellationToken).ConfigureAwait(false);
        request.MarkApplied(principal.UserObjectId, principal.UserPrincipalName, _clock.GetUtcNow(), note);

        // policy_changed: catalogued in EVENT_SCHEMAS since before this had a producer. The region
        // list itself is not re-read here to report a literal old-vs-new value — this event records
        // that an admin confirmed the change, not a diff this service computed, since the actual
        // change happened entirely outside it (the deploy script).
        await _audit.WriteAsync(new AuditEventDraft(
            "policy_changed",
            AuditSeverity.High,
            AuditComponent.ManagementUi,
            UserObjectId: principal.UserObjectId,
            UserPrincipalName: principal.UserPrincipalName,
            Data: new
            {
                policy_key = request.Kind is RegionChangeKind.Activate or RegionChangeKind.Deactivate
                    ? "Mina:Regions:Active" : "Mina:Regions:Approved",
                kind = request.Kind.ToString(),
                region = request.RegionName,
                resolution_note = request.ResolutionNote,
            }),
            cancellationToken).ConfigureAwait(false);

        await _requests.UpdateAsync(request, cancellationToken).ConfigureAwait(false);
        return RegionChangeRequestView.From(request);
    }

    public async Task<RegionChangeRequestView> DismissAsync(
        SessionPrincipal principal, Guid requestId, string reason, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);
        RequireRole(principal);

        var request = await RequireRequestAsync(requestId, cancellationToken).ConfigureAwait(false);
        request.Dismiss(principal.UserObjectId, principal.UserPrincipalName, _clock.GetUtcNow(), reason);

        await _audit.WriteAsync(new AuditEventDraft(
            "region_change_dismissed",
            AuditSeverity.Notice,
            AuditComponent.ManagementUi,
            UserObjectId: principal.UserObjectId,
            UserPrincipalName: principal.UserPrincipalName,
            Data: new { kind = request.Kind.ToString(), region = request.RegionName, reason = request.ResolutionNote }),
            cancellationToken).ConfigureAwait(false);

        await _requests.UpdateAsync(request, cancellationToken).ConfigureAwait(false);
        return RegionChangeRequestView.From(request);
    }

    public async Task<IReadOnlyList<RegionChangeRequestView>> ListPendingAsync(
        SessionPrincipal principal, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);
        RequireRole(principal);

        var pending = await _requests.ListPendingAsync(_options.PendingQueueLimit, cancellationToken).ConfigureAwait(false);
        return [.. pending.Select(RegionChangeRequestView.From)];
    }

    public async Task<IReadOnlyList<RegionChangeRequestView>> ListRecentlyResolvedAsync(
        SessionPrincipal principal, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);
        RequireRole(principal);

        var resolved = await _requests.ListRecentlyResolvedAsync(_options.RecentHistoryLimit, cancellationToken).ConfigureAwait(false);
        return [.. resolved.Select(RegionChangeRequestView.From)];
    }

    private async Task<RegionChangeRequest> RequireRequestAsync(Guid requestId, CancellationToken cancellationToken) =>
        await _requests.FindAsync(requestId, cancellationToken).ConfigureAwait(false)
        ?? throw new RegionChangeRequestNotFoundException(requestId);

    private void RequireRole(SessionPrincipal principal)
    {
        if (!principal.Roles.Contains(_options.AdminRole))
        {
            throw new RegionChangeRequestAuthorizationException();
        }
    }
}
