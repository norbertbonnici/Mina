using Mina.ControlPlane.Domain.Sessions;

namespace Mina.ControlPlane.Application.Sessions;

/// <summary>
/// The authenticated caller, projected from Entra token claims by the API layer. The control
/// plane authorises against this — never against anything the client asserts in the request body.
/// </summary>
/// <param name="UserObjectId">Entra object id (oid).</param>
/// <param name="UserPrincipalName">UPN / preferred_username.</param>
/// <param name="DeviceId">Entra device id (deviceid claim), if present.</param>
/// <param name="Roles">App roles from the token.</param>
/// <param name="DeviceBound">
/// Whether the token was issued through a device-bound flow, i.e. it carries a <c>deviceid</c>
/// claim. This proves the device is Entra-<em>registered</em> and that the token came from the
/// WAM/PRT path. It says nothing about Intune compliance: a registered device that is actively
/// non-compliant produces exactly the same claim. Compliance is proved by
/// <paramref name="AuthenticationContexts"/> when an auth context is configured.
/// </param>
/// <param name="AuthenticationContexts">
/// Conditional Access authentication-context ids from the <c>acrs</c> claim. Entra puts a value
/// here only when a CA policy bound to that auth context was actually satisfied for this token, so
/// requiring one is how a resource API can demand that the "require compliant device" grant was
/// evaluated — rather than assuming a policy exists somewhere in the tenant.
/// </param>
public sealed record SessionPrincipal(
    string UserObjectId,
    string UserPrincipalName,
    string? DeviceId,
    IReadOnlySet<string> Roles,
    bool DeviceBound,
    IReadOnlySet<string>? AuthenticationContexts = null);

/// <summary>A request to open a session: the chosen region and the endpoint-generated CSR.</summary>
/// <param name="Region">Requested egress region (validated against <c>RegionPolicy</c>).</param>
/// <param name="CertificateSigningRequest">DER-encoded PKCS#10 CSR; its key stays on the endpoint.</param>
public sealed record SessionIssueRequest(string Region, byte[] CertificateSigningRequest);

/// <summary>Egress ingress coordinates for a region (from configuration / the region directory).</summary>
public sealed record EgressEndpointInfo(string Host, int Port, string ServerName);

/// <summary>The result of a successful issue/renew: the signed certificate and where to tunnel.</summary>
public sealed record SessionGrant(
    Guid SessionId,
    byte[] IssuedCertificate,
    string CertificateSerialNumber,
    string Region,
    EgressEndpointInfo Egress,
    DateTimeOffset LeaseExpiresAt,
    SessionMode Mode);

/// <summary>Why a session request was refused. Each maps to an audit event (EVENT_SCHEMAS §3).</summary>
public enum SessionDenialReason
{
    NotAuthorisedRole,

    /// <summary>
    /// The token carries no <c>deviceid</c>, so it was not obtained through a device-bound flow.
    /// Previously called <c>DeviceNotCompliant</c>, which claimed more than the check performs.
    /// </summary>
    DeviceNotBound,

    /// <summary>
    /// A Conditional Access authentication context is required and the token does not carry it.
    /// Answered with a claims challenge rather than a flat refusal, so a compliant device can step
    /// up silently; a device that cannot satisfy the policy simply never gets the claim.
    /// </summary>
    AuthenticationContextRequired,

    RegionNotSelectable,
    InvalidCertificateRequest,
    NotSessionOwner,
    SessionNotFound,
}

/// <summary>Raised when a session operation is refused by authorisation policy.</summary>
public sealed class SessionAuthorizationException : Exception
{
    public SessionAuthorizationException(SessionDenialReason reason)
        : base($"Session request denied: {reason}.")
    {
        Reason = reason;
    }

    public SessionAuthorizationException(SessionDenialReason reason, string message)
        : base(message)
    {
        Reason = reason;
    }

    public SessionAuthorizationException()
    {
    }

    public SessionAuthorizationException(string message)
        : base(message)
    {
    }

    public SessionAuthorizationException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    public SessionDenialReason Reason { get; }
}

/// <summary>Resolves a region name to its egress ingress endpoint.</summary>
public interface IEgressDirectory
{
    EgressEndpointInfo? Resolve(string region);
}
