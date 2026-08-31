namespace Mina.ControlPlane.Domain.SensitiveSessions;

/// <summary>
/// States of a sensitive-session request, per ADR-0003 / ARCHITECTURE §7. "Normal" is the
/// absence of a request and is not modelled; a request begins at <see cref="Requested"/>.
/// </summary>
public enum SensitiveSessionState
{
    Requested,
    Approved,
    Denied,
    Cancelled,
    ActiveSuppressed,
    Ended,
}

/// <summary>Why an <see cref="SensitiveSessionState.Ended"/> state was reached.</summary>
public enum SensitiveSessionEndReason
{
    Expired,
    EndedEarly,
}
