namespace Mina.ControlPlane.Domain.Regions;

/// <summary>
/// Which egress regions an analyst may select. A region is selectable only if it is both on the
/// administrator-approved list (D-08) and currently active (a stamp is deployed and healthy,
/// ARCHITECTURE §8). Region names are the Azure names (e.g. "westeurope"), compared
/// case-insensitively. Enforcing this server-side is AC-008 — the client cannot widen the list.
/// </summary>
public sealed class RegionPolicy
{
    private readonly HashSet<string> _approved;
    private readonly HashSet<string> _active;

    public RegionPolicy(IEnumerable<string> approvedRegions, IEnumerable<string> activeRegions)
    {
        ArgumentNullException.ThrowIfNull(approvedRegions);
        ArgumentNullException.ThrowIfNull(activeRegions);
        _approved = new HashSet<string>(approvedRegions, StringComparer.OrdinalIgnoreCase);
        _active = new HashSet<string>(activeRegions, StringComparer.OrdinalIgnoreCase);

        var strayActive = _active.FirstOrDefault(r => !_approved.Contains(r));
        if (strayActive is not null)
        {
            throw new ArgumentException(
                $"Active region '{strayActive}' is not on the approved list.", nameof(activeRegions));
        }
    }

    /// <summary>Approved regions that currently have an active stamp — the analyst's choices.</summary>
    public IReadOnlyCollection<string> SelectableRegions =>
        _approved.Where(_active.Contains).OrderBy(r => r, StringComparer.Ordinal).ToArray();

    /// <summary>Every administrator-approved region, whether or not a stamp is running (D-08).</summary>
    public IReadOnlyCollection<string> ApprovedRegions =>
        _approved.OrderBy(r => r, StringComparer.Ordinal).ToArray();

    public bool IsApproved(string region) => region is not null && _approved.Contains(region);

    public bool IsSelectable(string region) =>
        region is not null && _approved.Contains(region) && _active.Contains(region);
}
