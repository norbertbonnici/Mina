using Mina.ControlPlane.Domain.Sessions;

namespace Mina.ControlPlane.Domain.Tests;

public class ResearchSessionTests
{
    private static readonly DateTimeOffset T0 = new(2026, 8, 31, 9, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan Lease = TimeSpan.FromMinutes(60);

    private static ResearchSession Issue() => ResearchSession.Issue(
        Guid.NewGuid(), "oid-1", "analyst@example.org", "device-1", "westeurope", T0, Lease, "SERIAL-1");

    [Fact]
    public void Issue_creates_an_active_session_with_a_lease()
    {
        var session = Issue();

        Assert.Equal(SessionState.Active, session.State);
        Assert.Equal(SessionMode.Normal, session.Mode);
        Assert.Equal(T0 + Lease, session.LeaseExpiresAt);
        Assert.True(session.IsUsableAt(T0.AddMinutes(30)));
    }

    [Fact]
    public void Renew_extends_the_lease_and_swaps_the_certificate_serial()
    {
        var session = Issue();

        session.Renew(T0.AddMinutes(50), Lease, "SERIAL-2");

        Assert.Equal(T0.AddMinutes(50) + Lease, session.LeaseExpiresAt);
        Assert.Equal("SERIAL-2", session.CertificateSerialNumber);
    }

    [Fact]
    public void Renew_after_the_lease_lapsed_is_rejected()
    {
        var session = Issue();

        var ex = Assert.Throws<SessionStateException>(() => session.Renew(T0.AddMinutes(61), Lease, "SERIAL-2"));
        Assert.Contains("lapsed", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void End_moves_to_ended_and_blocks_further_transitions()
    {
        var session = Issue();

        session.End(T0.AddMinutes(10), SessionEndReason.EndedByUser);

        Assert.Equal(SessionState.Ended, session.State);
        Assert.Equal(SessionEndReason.EndedByUser, session.EndReason);
        Assert.Throws<SessionStateException>(() => session.Renew(T0.AddMinutes(11), Lease, "SERIAL-2"));
    }

    [Fact]
    public void Revoke_is_allowed_from_active_and_records_the_actor()
    {
        var session = Issue();

        session.Revoke(T0.AddMinutes(5), "admin@example.org");

        Assert.Equal(SessionState.Revoked, session.State);
        Assert.Equal("admin@example.org", session.RevokedBy);
        Assert.False(session.IsUsableAt(T0.AddMinutes(6)));
    }

    [Fact]
    public void TryExpire_expires_only_a_lapsed_active_session()
    {
        var session = Issue();

        Assert.False(session.TryExpire(T0.AddMinutes(59)));
        Assert.True(session.TryExpire(T0.AddMinutes(60)));
        Assert.Equal(SessionState.Expired, session.State);

        // Idempotent: a second call does nothing.
        Assert.False(session.TryExpire(T0.AddMinutes(61)));
    }

    [Fact]
    public void MarkSensitive_switches_mode_only_while_active()
    {
        var session = Issue();
        session.MarkSensitive();
        Assert.Equal(SessionMode.Sensitive, session.Mode);

        session.End(T0.AddMinutes(10), SessionEndReason.EndedByUser);
        Assert.Throws<SessionStateException>(session.MarkSensitive);
    }
}
