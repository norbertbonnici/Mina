namespace Mina.ControlPlane.Domain.SensitiveSessions;

/// <summary>
/// Governance policy values for sensitive sessions. Configured by administrators (no default is
/// baked in — LOGGING_AND_PRIVACY prohibits implicit policy) and recorded with each decision.
/// </summary>
/// <param name="MaxDuration">Upper bound for requested durations and approval TTLs.</param>
public sealed record SensitiveSessionPolicy(TimeSpan MaxDuration)
{
    public bool IsWithinLimit(TimeSpan duration) => duration > TimeSpan.Zero && duration <= MaxDuration;
}
