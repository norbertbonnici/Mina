using Mina.ControlPlane.Pki;

namespace Mina.ControlPlane.Pki.Tests;

/// <summary>
/// CA rotation urgency classification (M4-2). Pure threshold arithmetic, tested without touching
/// Key Vault or a real certificate -- the interesting behaviour is entirely in the boundaries.
/// </summary>
public sealed class CaRotationStatusTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 10, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Well_before_the_warn_window_is_healthy()
    {
        var status = CaRotationStatus.Classify(Now.AddDays(1000), Now);

        Assert.Equal(RotationUrgency.Healthy, status.Urgency);
        Assert.Equal(1000, status.DaysRemaining);
    }

    [Fact]
    public void Exactly_at_the_warn_boundary_is_warning_not_healthy()
    {
        // <= warnBefore is Warning, not < -- a certificate expiring in exactly the warn window
        // should not silently read as healthy on the one day that boundary matters most.
        var status = CaRotationStatus.Classify(
            Now + CaRotationStatus.DefaultWarnBefore, Now);

        Assert.Equal(RotationUrgency.Warning, status.Urgency);
    }

    [Fact]
    public void Just_inside_the_warn_window_is_warning()
    {
        var status = CaRotationStatus.Classify(
            Now + CaRotationStatus.DefaultWarnBefore - TimeSpan.FromDays(1), Now);

        Assert.Equal(RotationUrgency.Warning, status.Urgency);
    }

    [Fact]
    public void Exactly_at_the_critical_boundary_is_critical_not_warning()
    {
        var status = CaRotationStatus.Classify(
            Now + CaRotationStatus.DefaultCriticalBefore, Now);

        Assert.Equal(RotationUrgency.Critical, status.Urgency);
    }

    [Fact]
    public void An_already_expired_certificate_is_critical_with_negative_days_remaining()
    {
        var status = CaRotationStatus.Classify(Now.AddDays(-5), Now);

        Assert.Equal(RotationUrgency.Critical, status.Urgency);
        Assert.Equal(-5, status.DaysRemaining);
    }

    [Fact]
    public void Custom_thresholds_override_the_defaults()
    {
        var status = CaRotationStatus.Classify(
            Now.AddDays(20), Now, warnBefore: TimeSpan.FromDays(30), criticalBefore: TimeSpan.FromDays(10));

        // 20 days remaining: inside the custom 30-day warn window, outside the custom 10-day
        // critical one -- proves the parameters are actually used, not just accepted and ignored.
        Assert.Equal(RotationUrgency.Warning, status.Urgency);
    }

    [Fact]
    public void A_critical_window_wider_than_the_warn_window_is_rejected()
    {
        // Critical is meant to be the narrower, more urgent window nested inside Warning. Accepting
        // the inverted case would make "Critical" trigger before "Warning" ever could, silently
        // producing a rotation check that jumps straight from Healthy to Critical.
        var ex = Assert.Throws<ArgumentException>(() => CaRotationStatus.Classify(
            Now.AddDays(100), Now, warnBefore: TimeSpan.FromDays(30), criticalBefore: TimeSpan.FromDays(90)));

        Assert.Contains("must not exceed", ex.Message, StringComparison.Ordinal);
    }
}
