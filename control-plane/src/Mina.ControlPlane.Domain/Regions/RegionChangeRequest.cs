namespace Mina.ControlPlane.Domain.Regions;

/// <summary>What kind of change to the region list is being asked for (ADR-0008 Option C).</summary>
public enum RegionChangeKind
{
    /// <summary>Add a region to the administrator-approved list (D-08).</summary>
    AddApproved,

    /// <summary>Remove a region from the approved list.</summary>
    RemoveApproved,

    /// <summary>Mark an approved region active/selectable — requires a deployed, healthy stamp first.</summary>
    Activate,

    /// <summary>Mark a region no longer selectable, without removing it from the approved list.</summary>
    Deactivate,
}

/// <summary>Where a request sits. There is no "approved" status distinct from "applied": unlike
/// <c>SensitiveSessionRequest</c>, this workflow does not itself authorize the change — the reviewed
/// deploy-script run does — so there is nothing for a second party to approve here, only to confirm
/// has actually happened (ADR-0008).</summary>
public enum RegionChangeRequestStatus
{
    Pending,
    Applied,
    Dismissed,
}

public enum RegionChangeRule
{
    ActorRequired,
    RegionNameRequired,
    JustificationRequired,
    ResolutionNoteRequired,
    InvalidTransition,
}

public sealed class RegionChangeRuleViolationException(RegionChangeRule rule, string message) : Exception(message)
{
    public RegionChangeRule Rule { get; } = rule;
}

/// <summary>
/// A request to change the approved/active region list (ADR-0008 Option C, backlog M3-2). This
/// aggregate captures and audits intent; it does not itself change
/// <c>Mina:Regions:Approved</c>/<c>Active</c> or the region a device actually sees, both of which
/// stay entirely IaC-owned (<c>deploy-control-plane-api-windows.ps1</c>/
/// <c>deploy-management-ui-windows.ps1</c>'s own parameters). "Applied" here means an admin has
/// confirmed the real deploy actually happened, not that this record caused it — deliberately, so
/// there is exactly one place (the reviewed script run) with authority to change where research
/// traffic can exit, matching CLAUDE.md's stop condition on changing that strategy.
/// </summary>
public sealed class RegionChangeRequest
{
    /// <summary>Longest justification accepted. Free text, not a reference (unlike
    /// <c>SensitiveSessionRequest.JustificationReference</c>) — a region change is an infrastructure
    /// decision, not something threat N4's justification-content concern applies to.</summary>
    public const int MaxJustificationLength = 1024;

    /// <summary>Matches Azure region naming (e.g. "spaincentral") -- lowercase ASCII letters and
    /// digits only, the same alphabet <c>RegionPolicy</c> already compares case-insensitively.</summary>
    public const int MaxRegionNameLength = 64;

    private RegionChangeRequest(
        Guid id,
        string requestedByObjectId,
        string requestedByUpn,
        RegionChangeKind kind,
        string regionName,
        string justification,
        DateTimeOffset requestedAt)
    {
        Id = id;
        RequestedByObjectId = requestedByObjectId;
        RequestedByUpn = requestedByUpn;
        Kind = kind;
        RegionName = regionName;
        Justification = justification;
        RequestedAt = requestedAt;
        Status = RegionChangeRequestStatus.Pending;
    }

    public Guid Id { get; }

    public string RequestedByObjectId { get; }

    public string RequestedByUpn { get; }

    public RegionChangeKind Kind { get; }

    /// <summary>Normalised lowercase, e.g. "spaincentral".</summary>
    public string RegionName { get; }

    public string Justification { get; }

    public DateTimeOffset RequestedAt { get; }

    public RegionChangeRequestStatus Status { get; private set; }

    public string? ResolvedByObjectId { get; private set; }

    public string? ResolvedByUpn { get; private set; }

    public DateTimeOffset? ResolvedAt { get; private set; }

    /// <summary>How it was resolved — e.g. which deploy actually applied it, or why it was dismissed.</summary>
    public string? ResolutionNote { get; private set; }

    public static RegionChangeRequest Create(
        Guid id,
        string requestedByObjectId,
        string requestedByUpn,
        RegionChangeKind kind,
        string regionName,
        string justification,
        DateTimeOffset requestedAt)
    {
        if (string.IsNullOrWhiteSpace(requestedByObjectId) || string.IsNullOrWhiteSpace(requestedByUpn))
        {
            throw new RegionChangeRuleViolationException(
                RegionChangeRule.ActorRequired, "A requester identity is required.");
        }

        var normalizedRegion = (regionName ?? string.Empty).Trim().ToLowerInvariant();
        if (normalizedRegion.Length == 0
            || normalizedRegion.Length > MaxRegionNameLength
            || !normalizedRegion.All(c => (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')))
        {
            throw new RegionChangeRuleViolationException(
                RegionChangeRule.RegionNameRequired,
                $"Region name is required, lowercase ASCII letters/digits only (Azure region naming), at most {MaxRegionNameLength} characters.");
        }

        var trimmedJustification = (justification ?? string.Empty).Trim();
        if (trimmedJustification.Length == 0 || trimmedJustification.Length > MaxJustificationLength)
        {
            throw new RegionChangeRuleViolationException(
                RegionChangeRule.JustificationRequired,
                $"A justification is required, of at most {MaxJustificationLength} characters.");
        }

        return new RegionChangeRequest(
            id, requestedByObjectId, requestedByUpn, kind, normalizedRegion, trimmedJustification, requestedAt);
    }

    /// <summary>
    /// An admin confirms the change was actually applied through the reviewed deploy path.
    /// Deliberately not restricted to "not the requester" the way <c>SensitiveSessionRequest.Approve</c>
    /// is — there is no second-party-authorization property here to protect, since this call records
    /// that infrastructure work already happened, it does not authorize the work itself.
    /// </summary>
    public void MarkApplied(string byObjectId, string byUpn, DateTimeOffset now, string? note)
    {
        RequireActor(byObjectId, byUpn);
        RequireState(RegionChangeRequestStatus.Pending, nameof(MarkApplied));

        Status = RegionChangeRequestStatus.Applied;
        ResolvedByObjectId = byObjectId;
        ResolvedByUpn = byUpn;
        ResolvedAt = now;
        ResolutionNote = note?.Trim();
    }

    /// <summary>An admin declines to pursue the request — e.g. superseded, not going to happen.</summary>
    public void Dismiss(string byObjectId, string byUpn, DateTimeOffset now, string reason)
    {
        RequireActor(byObjectId, byUpn);
        RequireState(RegionChangeRequestStatus.Pending, nameof(Dismiss));

        var trimmedReason = (reason ?? string.Empty).Trim();
        if (trimmedReason.Length == 0)
        {
            throw new RegionChangeRuleViolationException(
                RegionChangeRule.ResolutionNoteRequired, "A reason is required to dismiss a request.");
        }

        Status = RegionChangeRequestStatus.Dismissed;
        ResolvedByObjectId = byObjectId;
        ResolvedByUpn = byUpn;
        ResolvedAt = now;
        ResolutionNote = trimmedReason;
    }

    private static void RequireActor(string objectId, string upn)
    {
        if (string.IsNullOrWhiteSpace(objectId) || string.IsNullOrWhiteSpace(upn))
        {
            throw new RegionChangeRuleViolationException(RegionChangeRule.ActorRequired, "An acting identity is required.");
        }
    }

    private void RequireState(RegionChangeRequestStatus expected, string operation)
    {
        if (Status != expected)
        {
            throw new RegionChangeRuleViolationException(
                RegionChangeRule.InvalidTransition, $"{operation} is not valid from status {Status}.");
        }
    }
}
