using Mina.EgressNode.Sidecar;

namespace Mina.EgressNode.Sidecar.Tests;

/// <summary>
/// Node-side admission (M4-11): whether Envoy opens a tunnel for a certificate is decided against
/// the control plane's current session list rather than by certificate validity alone. Every case
/// that is not a clear "yes" must be a "no" — the rule fails closed by construction, and these tests
/// enumerate the ways it must.
/// </summary>
public class NodeSessionViewAdmissionTests
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 2, 9, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan MaxAge = TimeSpan.FromMinutes(5);

    [Fact]
    public void Nothing_is_admitted_before_the_first_successful_refresh()
    {
        var clock = new TestClock(T0);
        var view = new NodeSessionView();

        Assert.Equal(Admission.ViewNotLoaded, view.Admit(Guid.NewGuid(), clock, MaxAge));
        Assert.Null(view.LastRefreshedAt);
        Assert.Null(view.Age(clock));
        Assert.False(view.IsFresh(clock, MaxAge));
    }

    [Fact]
    public void A_listed_session_with_a_current_lease_is_admitted()
    {
        var clock = new TestClock(T0);
        var session = Guid.NewGuid();
        var view = new NodeSessionView();
        view.Update([new NodeSession(session, false, T0.AddMinutes(45))], clock);

        clock.Now = T0.AddSeconds(10);
        Assert.Equal(Admission.Admitted, view.Admit(session, clock, MaxAge));
        Assert.Equal(T0, view.LastRefreshedAt);
        Assert.Equal(TimeSpan.FromSeconds(10), view.Age(clock));
    }

    [Fact]
    public void A_suppressed_session_is_still_admitted()
    {
        // Suppression is about what is recorded, not whether the analyst may browse.
        var clock = new TestClock(T0);
        var session = Guid.NewGuid();
        var view = new NodeSessionView();
        view.Update([new NodeSession(session, Suppressed: true, T0.AddMinutes(45))], clock);

        Assert.Equal(Admission.Admitted, view.Admit(session, clock, MaxAge));
        Assert.True(view.MustWithholdDestination(session));
    }

    [Fact]
    public void A_session_the_control_plane_no_longer_lists_is_refused()
    {
        // The revocation case. The certificate is still valid; the session is not.
        var clock = new TestClock(T0);
        var session = Guid.NewGuid();
        var view = new NodeSessionView();
        view.Update([new NodeSession(session, false, T0.AddMinutes(45))], clock);
        Assert.Equal(Admission.Admitted, view.Admit(session, clock, MaxAge));

        clock.Now = T0.AddSeconds(15);
        view.Update([], clock);

        Assert.Equal(Admission.UnknownSession, view.Admit(session, clock, MaxAge));
    }

    [Fact]
    public void A_session_never_issued_is_refused()
    {
        var clock = new TestClock(T0);
        var view = new NodeSessionView();
        view.Update([new NodeSession(Guid.NewGuid(), false, T0.AddMinutes(45))], clock);

        Assert.Equal(Admission.UnknownSession, view.Admit(Guid.NewGuid(), clock, MaxAge));
    }

    [Fact]
    public void A_listed_session_whose_lease_ran_out_since_the_refresh_is_refused()
    {
        var clock = new TestClock(T0);
        var session = Guid.NewGuid();
        var view = new NodeSessionView();
        view.Update([new NodeSession(session, false, T0.AddSeconds(20))], clock);

        clock.Now = T0.AddSeconds(19);
        Assert.Equal(Admission.Admitted, view.Admit(session, clock, MaxAge));
        clock.Now = T0.AddSeconds(20);
        Assert.Equal(Admission.LeaseLapsed, view.Admit(session, clock, MaxAge));
    }

    [Fact]
    public void A_view_older_than_the_node_may_trust_refuses_everything_it_lists()
    {
        // The fail-closed half of the decision. Past maxAge the node cannot know which of the
        // sessions it still lists have been revoked, so it serves none of them. Refusing a session
        // that is in the list is the point, not a side effect.
        var clock = new TestClock(T0);
        var session = Guid.NewGuid();
        var view = new NodeSessionView();
        view.Update([new NodeSession(session, false, T0.AddHours(1))], clock);

        clock.Now = T0 + MaxAge;
        Assert.Equal(Admission.Admitted, view.Admit(session, clock, MaxAge));
        clock.Now = T0 + MaxAge + TimeSpan.FromSeconds(1);
        Assert.Equal(Admission.ViewStale, view.Admit(session, clock, MaxAge));
        Assert.False(view.IsFresh(clock, MaxAge));
    }

    [Fact]
    public void A_refresh_makes_a_stale_view_current_again()
    {
        var clock = new TestClock(T0);
        var session = Guid.NewGuid();
        var view = new NodeSessionView();
        view.Update([new NodeSession(session, false, T0.AddHours(1))], clock);
        clock.Now = T0.AddMinutes(10);
        Assert.Equal(Admission.ViewStale, view.Admit(session, clock, MaxAge));

        view.Update([new NodeSession(session, false, clock.Now.AddHours(1))], clock);

        Assert.Equal(Admission.Admitted, view.Admit(session, clock, MaxAge));
    }

    [Fact]
    public void Staleness_is_judged_against_the_last_successful_refresh_not_the_last_attempt()
    {
        // A failed refresh does not call Update, so the view's age keeps growing through an outage
        // and the age check is what eventually refuses. This pins that Update is the only thing
        // that resets the clock.
        var clock = new TestClock(T0);
        var session = Guid.NewGuid();
        var view = new NodeSessionView();
        view.Update([new NodeSession(session, false, T0.AddHours(1))], clock);

        // (an outage: nothing calls Update)
        clock.Now = T0.AddMinutes(6);

        Assert.Equal(Admission.ViewStale, view.Admit(session, clock, MaxAge));
        Assert.Equal(T0, view.LastRefreshedAt);
    }

    [Fact]
    public void Age_follows_the_monotonic_clock_not_wall_time()
    {
        // An NTP step on the node must neither mark a fresh view stale nor hide a stale one. The
        // clock here moves its monotonic timestamp and its wall time independently.
        var clock = new SplitClock(T0);
        var session = Guid.NewGuid();
        var view = new NodeSessionView();
        view.Update([new NodeSession(session, false, T0.AddHours(1))], clock);

        clock.WallTime = T0.AddHours(-2);   // wall clock stepped back two hours; 10 s really passed
        clock.Monotonic = T0.AddSeconds(10);
        Assert.Equal(TimeSpan.FromSeconds(10), view.Age(clock));
        Assert.Equal(Admission.Admitted, view.Admit(session, clock, MaxAge));

        clock.WallTime = T0.AddSeconds(20);  // wall clock corrected; 10 minutes really passed
        clock.Monotonic = T0.AddMinutes(10);
        Assert.Equal(Admission.ViewStale, view.Admit(session, clock, MaxAge));
    }

    private sealed class SplitClock(DateTimeOffset start) : TimeProvider
    {
        public DateTimeOffset WallTime { get; set; } = start;

        public DateTimeOffset Monotonic { get; set; } = start;

        public override DateTimeOffset GetUtcNow() => WallTime;

        public override long GetTimestamp() => Monotonic.UtcTicks;

        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
    }
}

/// <summary>
/// Reading the session id from the principal Envoy reports for the verified certificate. The
/// interesting cases are what Envoy sends when the certificate is not a Mina session certificate —
/// and the rule that anything of that kind is a refusal.
/// </summary>
public class SessionPrincipalTests
{
    private const string Session = "6f1c2b7e-6c9a-4a3d-9a1e-2b7c4d5e6f70";

    [Fact]
    public void Reads_the_session_from_its_uri()
    {
        Assert.Equal(Guid.Parse(Session), SessionPrincipal.TryParse($"mina:session:{Session}"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("client.example")]                                      // Envoy fell back to a DNS SAN
    [InlineData("CN=mina-session,O=Mina")]                              // or to the subject
    [InlineData("spiffe://cluster.local/ns/x/sa/y")]                    // a foreign URI scheme
    [InlineData("mina:session:")]                                       // empty id
    [InlineData("mina:session:not-a-guid")]
    [InlineData("mina:session:{" + Session + "}")]                      // braces: not the issued form
    [InlineData("mina:session:" + Session + "x")]                       // trailing garbage
    [InlineData(" mina:session:" + Session)]                            // leading whitespace
    [InlineData("mina:session:00000000-0000-0000-0000-000000000000")]
    [InlineData("MINA:SESSION:" + Session)]                             // scheme is case-sensitive as issued
    public void Anything_that_is_not_exactly_a_session_uri_is_refused(string? principal)
    {
        Assert.Null(SessionPrincipal.TryParse(principal));
    }
}

public class AdmissionMissLimiterTests
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 2, 9, 0, 0, TimeSpan.Zero);

    [Fact]
    public void One_refresh_per_unknown_session_per_interval()
    {
        var clock = new TestClock(T0);
        var limiter = new AdmissionMissLimiter();
        var session = Guid.NewGuid();
        var interval = TimeSpan.FromSeconds(15);

        Assert.True(limiter.ShouldRefreshFor(session, clock, interval));
        clock.Now = T0.AddSeconds(5);
        Assert.False(limiter.ShouldRefreshFor(session, clock, interval));
        clock.Now = T0.AddSeconds(15);
        Assert.True(limiter.ShouldRefreshFor(session, clock, interval));
    }

    [Fact]
    public void Sessions_are_limited_independently()
    {
        var clock = new TestClock(T0);
        var limiter = new AdmissionMissLimiter();

        Assert.True(limiter.ShouldRefreshFor(Guid.NewGuid(), clock, TimeSpan.FromSeconds(15)));
        Assert.True(limiter.ShouldRefreshFor(Guid.NewGuid(), clock, TimeSpan.FromSeconds(15)));
    }
}
