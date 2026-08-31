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
/// <param name="DeviceCompliant">
/// Whether the device meets compliance. Conditional Access is the authoritative gate at token
/// issuance (SR-007); this flag lets the control plane additionally refuse if the signal is absent.
/// </param>
public sealed record SessionPrincipal(
    string UserObjectId,
    string UserPrincipalName,
    string? DeviceId,
    IReadOnlySet<string> Roles,
    bool DeviceCompliant);

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
    DeviceNotCompliant,
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
