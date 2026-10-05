using System.Security.Claims;
using Mina.ControlPlane.Domain.Regions;

namespace Mina.ControlPlane.Application.Telemetry;

/// <summary>
/// Which egress regions a calling node is entitled to act for.
/// </summary>
/// <remarks>
/// Holding the node role says a caller is <em>a</em> node; it does not say which one. Without a
/// second dimension, any node could read another region's session allowlist and post telemetry
/// against another region's sessions — the exact scoping THREAT_MODEL B4 names as the mitigation
/// ("the API scopes the node identity to its own region's allowlist and telemetry ingest only").
///
/// The grant is carried as app roles of the form <c>Mina.Node.&lt;region&gt;</c>, which Entra can
/// assign to a node's managed identity per stamp. A node with the bare node role and no region
/// grant is entitled to nothing: a node that cannot say which region it serves has no business
/// reading any region's sessions.
/// </remarks>
public static class NodeRegionGrant
{
    public const string RolePrefix = "Mina.Node.";

    /// <summary>The regions this principal may act for, lower-cased. Empty means none.</summary>
    public static IReadOnlySet<string> RegionsFor(ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);

        var regions = principal.FindAll("roles").Select(c => c.Value)
            .Concat(principal.FindAll(ClaimTypes.Role).Select(c => c.Value))
            .Where(role => role.StartsWith(RolePrefix, StringComparison.OrdinalIgnoreCase))
            .Select(role => role[RolePrefix.Length..].ToLowerInvariant())
            .Where(RegionName.IsWellFormed)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        return regions;
    }

    /// <summary>True if the principal may act for <paramref name="region"/>.</summary>
    public static bool IsGrantedFor(ClaimsPrincipal principal, string region) =>
        RegionName.IsWellFormed(region) && RegionsFor(principal).Contains(region);
}
