using Mina.ControlPlane.Domain.SensitiveSessions;

namespace Mina.ControlPlane.Application.SensitiveSessions;

/// <summary>A sensitive-session request as presented to callers.</summary>
public sealed record SensitiveSessionView(
    Guid RequestId,
    Guid SessionId,
    string RequesterUpn,
    string JustificationReference,
    TimeSpan RequestedDuration,
    DateTimeOffset RequestedAt,
    SensitiveSessionState State,
    string? ApproverUpn,
    DateTimeOffset? ApprovedAt,
    DateTimeOffset? ExpiresAt,
    DateTimeOffset? ActivatedAt)
{
    public static SensitiveSessionView From(SensitiveSessionRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return new SensitiveSessionView(
            request.Id,
            request.SessionId,
            request.RequesterUpn,
            request.JustificationReference,
            request.RequestedDuration,
            request.RequestedAt,
            request.State,
            request.ApproverUpn,
            request.ApprovedAt,
            request.ExpiresAt,
            request.ActivatedAt);
    }
}

/// <summary>Why a sensitive-session operation was refused.</summary>
public enum SensitiveSessionDenialReason
{
    NotAuthorisedRole,
    NotRequester,
    RequestNotFound,
    SessionNotFound,
    SessionNotUsable,
}

/// <summary>Raised when a sensitive-session operation is refused by authorisation policy.</summary>
public sealed class SensitiveSessionAuthorizationException : Exception
{
    public SensitiveSessionAuthorizationException(SensitiveSessionDenialReason reason)
        : base($"Sensitive-session request denied: {reason}.")
    {
        Reason = reason;
    }

    public SensitiveSessionAuthorizationException(SensitiveSessionDenialReason reason, string message)
        : base(message)
    {
        Reason = reason;
    }

    public SensitiveSessionAuthorizationException()
    {
    }

    public SensitiveSessionAuthorizationException(string message)
        : base(message)
    {
    }

    public SensitiveSessionAuthorizationException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    public SensitiveSessionDenialReason Reason { get; }
}
