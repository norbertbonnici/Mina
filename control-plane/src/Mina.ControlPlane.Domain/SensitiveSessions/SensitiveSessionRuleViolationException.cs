namespace Mina.ControlPlane.Domain.SensitiveSessions;

/// <summary>Rule identifiers for governance violations, stable for audit/event payloads.</summary>
public enum SensitiveSessionRule
{
    JustificationRequired,
    ActorRequired,
    SessionRequired,
    DurationOutOfRange,
    TtlOutOfRange,
    InvalidTransition,
    SelfApprovalForbidden,
    NotRequester,
    ApprovalWindowElapsed,

    /// <summary>
    /// The session already has a request awaiting a decision. One at a time: nothing else caps how
    /// many requests an analyst may raise, and the approver queue is where volume from one analyst
    /// buries another's.
    /// </summary>
    RequestAlreadyPending,
}

/// <summary>Thrown when a sensitive-session operation violates an ADR-0003 governance rule.</summary>
public sealed class SensitiveSessionRuleViolationException : Exception
{
    public SensitiveSessionRuleViolationException()
    {
    }

    public SensitiveSessionRuleViolationException(string message)
        : base(message)
    {
    }

    public SensitiveSessionRuleViolationException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    public SensitiveSessionRuleViolationException(SensitiveSessionRule rule, string message)
        : base(message)
    {
        Rule = rule;
    }

    public SensitiveSessionRule Rule { get; }
}
