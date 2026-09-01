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

    /// <summary>Conditional Access authentication contexts satisfied for this token.</summary>
    private const string AuthContextClaim = "acrs";

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

        // A deviceid claim means the token came from a device-bound (WAM/PRT) flow on an
        // Entra-registered device. It is deliberately NOT called compliance: an Entra token carries
        // no Intune compliance claim, and a registered device that is failing its compliance policy
        // emits the same deviceid. Compliance is proved by acrs, below, when the deployment
        // configures an authentication context for it.
        var deviceBound = !string.IsNullOrEmpty(deviceId);

        var authContexts = user.FindAll(AuthContextClaim)
            .Select(c => c.Value)
            .ToHashSet(StringComparer.Ordinal);

        return new SessionPrincipal(objectId, upn, deviceId, roles, deviceBound, authContexts);
    }
}
