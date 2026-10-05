using Mina.EndpointAgent.Session;

namespace Mina.EndpointAgent.Tests.Session;

/// <summary>
/// The agent's half of the M2-4 token relay: the tray hands over what it acquired from the WAM
/// broker, and this is what <see cref="ControlPlaneClient"/> actually reads from on every call.
/// </summary>
public sealed class TrayFedAccessTokenProviderTests
{
    private static readonly DateTimeOffset Start = new(2026, 9, 1, 14, 0, 0, TimeSpan.Zero);

    private readonly MutableTimeProvider _clock = new(Start);
    private readonly TrayFedAccessTokenProvider _provider;

    public TrayFedAccessTokenProviderTests() => _provider = new TrayFedAccessTokenProvider(_clock);

    [Fact]
    public async Task No_token_yet_is_a_distinguishable_failure()
    {
        await Assert.ThrowsAsync<NoAccessTokenAvailableException>(
            () => _provider.GetAccessTokenAsync(CancellationToken.None));
    }

    [Fact]
    public async Task A_submitted_token_is_returned_until_it_nears_expiry()
    {
        _provider.Submit("token-1", Start.AddMinutes(60));

        Assert.Equal("token-1", await _provider.GetAccessTokenAsync(CancellationToken.None));
    }

    [Fact]
    public async Task A_token_stops_being_offered_before_it_actually_expires()
    {
        // A request in flight must not race the tray's own refresh and be handed a token that
        // expires mid-request, so the provider stops offering it some margin before the real expiry.
        _provider.Submit("token-1", Start.AddMinutes(60));

        _clock.Advance(TimeSpan.FromMinutes(59));

        await Assert.ThrowsAsync<NoAccessTokenAvailableException>(
            () => _provider.GetAccessTokenAsync(CancellationToken.None));
    }

    [Fact]
    public async Task A_fresh_submission_replaces_an_expiring_one()
    {
        _provider.Submit("token-1", Start.AddMinutes(60));
        _clock.Advance(TimeSpan.FromMinutes(59));

        _provider.Submit("token-2", Start.AddMinutes(120));

        Assert.Equal("token-2", await _provider.GetAccessTokenAsync(CancellationToken.None));
    }

    [Fact]
    public void No_claims_challenge_is_outstanding_by_default() => Assert.Null(_provider.RequiredClaims);

    [Fact]
    public void A_recorded_claims_challenge_is_reported_verbatim()
    {
        const string claims = """{"access_token":{"acrs":{"essential":true,"value":"c1"}}}""";

        _provider.RecordClaimsChallenge(claims);

        Assert.Equal(claims, _provider.RequiredClaims);
    }

    [Fact]
    public void Submitting_a_token_clears_a_pending_claims_challenge()
    {
        _provider.RecordClaimsChallenge("""{"access_token":{"acrs":{"essential":true,"value":"c1"}}}""");

        _provider.Submit("token-1", Start.AddMinutes(60));

        Assert.Null(_provider.RequiredClaims);
    }
}
