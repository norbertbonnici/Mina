using System.Text.RegularExpressions;

namespace Mina.ControlPlane.Domain.Regions;

/// <summary>
/// Shape check for an Azure region name as supplied by a client.
/// </summary>
/// <remarks>
/// A region arrives from the endpoint agent and from egress nodes, and downstream it becomes a
/// metric dimension and an audit-event field. Both need it bounded before it is used: an unbounded
/// value inflates metric cardinality, could carry a destination into operational telemetry, and —
/// if long enough to exceed the audit payload column — makes the audit write fail, which under
/// audit-before-act means the caller can stop their own denial from being recorded. Rejecting a
/// malformed region at the boundary closes all three.
///
/// This is a shape check only. Whether a well-formed region is approved and active is
/// <see cref="RegionPolicy"/>'s decision.
/// </remarks>
public static partial class RegionName
{
    public const int MaxLength = 40;

    /// <summary>True if the value could be an Azure region name (e.g. "westeurope").</summary>
    public static bool IsWellFormed(string? value) =>
        !string.IsNullOrEmpty(value) && value.Length <= MaxLength && Pattern().IsMatch(value);

    [GeneratedRegex(@"^[a-z][a-z0-9]*$", RegexOptions.CultureInvariant)]
    private static partial Regex Pattern();
}
