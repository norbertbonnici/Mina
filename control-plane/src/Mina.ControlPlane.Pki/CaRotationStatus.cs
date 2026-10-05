namespace Mina.ControlPlane.Pki;

/// <summary>How urgently the CA certificate needs rolling over (M4-2).</summary>
public enum RotationUrgency
{
    /// <summary>More than <c>warnBefore</c> remains. Nothing to do.</summary>
    Healthy,

    /// <summary>Inside <c>warnBefore</c> of expiry — start planning a rollover.</summary>
    Warning,

    /// <summary>Inside <c>criticalBefore</c> of expiry, or already expired.</summary>
    Critical,
}

/// <summary>
/// Classifies how close a certificate is to needing rotation. Deliberately a pure function over
/// <see cref="DateTimeOffset"/> values rather than something that reads a live certificate itself —
/// the interesting behaviour here is the threshold arithmetic, and keeping it free of
/// <c>X509Certificate2</c>/Key Vault entirely is what makes it unit-testable without a vault, the
/// same reason <c>RegionPolicy</c> stays a plain class with no I/O of its own.
/// </summary>
public sealed record CaRotationStatus(RotationUrgency Urgency, int DaysRemaining)
{
    /// <summary>
    /// The internal CA's own default (5-year lifetime, <c>mina-ca bootstrap</c>'s own default)
    /// suggests these as reasonable defaults: a year's notice is enough to plan and test a
    /// rollover (which touches every endpoint agent package, not just the control plane) without
    /// being so early it is noise for years at a time; 90 days is "this needs to be on someone's
    /// plan now, not eventually."
    /// </summary>
    public static readonly TimeSpan DefaultWarnBefore = TimeSpan.FromDays(365);

    public static readonly TimeSpan DefaultCriticalBefore = TimeSpan.FromDays(90);

    public static CaRotationStatus Classify(
        DateTimeOffset notAfter, DateTimeOffset now, TimeSpan? warnBefore = null, TimeSpan? criticalBefore = null)
    {
        var warn = warnBefore ?? DefaultWarnBefore;
        var critical = criticalBefore ?? DefaultCriticalBefore;
        if (critical > warn)
        {
            throw new ArgumentException(
                $"{nameof(criticalBefore)} ({critical}) must not exceed {nameof(warnBefore)} ({warn}) -- " +
                "critical is the narrower, more urgent window.");
        }

        var remaining = notAfter - now;
        var daysRemaining = (int)Math.Floor(remaining.TotalDays);

        var urgency = remaining <= critical
            ? RotationUrgency.Critical
            : remaining <= warn
                ? RotationUrgency.Warning
                : RotationUrgency.Healthy;

        return new CaRotationStatus(urgency, daysRemaining);
    }
}
