using System.Security.Claims;

namespace Mina.ControlPlane.Application.Sessions;

/// <summary>
/// Projects a validated Entra <see cref="ClaimsPrincipal"/> into a <see cref="SessionPrincipal"/>.
/// Identity, roles and device come from the token only.
/// </summary>
public static class ClaimsPrincipalExtensions
{
    // Entra object id claim (short and full URI forms).
    private const string ObjectIdClaim = "oid";
    private const string ObjectIdClaimUri = "http://schemas.microsoft.com/identity/claims/objectidentifier";
    private const string DeviceIdClaim = "deviceid";
    private const string RolesClaim = "roles";

    public static SessionPrincipal ToSessionPrincipal(this ClaimsPrincipal user)
    {
        ArgumentNullException.ThrowIfNull(user);

        var objectId = user.FindFirst(ObjectIdClaim)?.Value
            ?? user.FindFirst(ObjectIdClaimUri)?.Value
            ?? throw new InvalidOperationException("Token is missing the object identifier (oid) claim.");

        var upn = user.FindFirst("preferred_username")?.Value
            ?? user.FindFirst(ClaimTypes.Upn)?.Value
            ?? user.Identity?.Name
            ?? objectId;

        var deviceId = user.FindFirst(DeviceIdClaim)?.Value;

        var roles = user.FindAll(RolesClaim).Select(c => c.Value)
            .Concat(user.FindAll(ClaimTypes.Role).Select(c => c.Value))
            .ToHashSet(StringComparer.Ordinal);

        // Conditional Access is the authoritative device-compliance gate at token issuance
        // (SR-007). Absent a dedicated compliance claim, the control plane treats the presence of
        // a device id as the managed-device signal and refuses otherwise. A first-class compliance
        // signal can be wired here without touching the domain.
        var deviceCompliant = !string.IsNullOrEmpty(deviceId);

        return new SessionPrincipal(objectId, upn, deviceId, roles, deviceCompliant);
    }
}
