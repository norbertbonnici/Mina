using System.Net;
using System.Net.Http.Json;
using System.Text;
using Mina.EndpointAgent.Session;

namespace Mina.EndpointAgent.Tests.Session;

/// <summary>
/// The client side of ARCHITECTURE §4's claims-challenge protocol: the control plane's
/// <c>ClaimsChallengeResult</c> is the server half, this is what has to decode exactly what it
/// sent so the token provider learns what to re-acquire with (M2-4).
/// </summary>
public sealed class ControlPlaneClientTests
{
    private static string EncodeChallenge(string authContextId)
    {
        var claims = "{\"access_token\":{\"acrs\":{\"essential\":true,\"value\":\"" + authContextId + "\"}}}";
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(claims));
    }

    [Fact]
    public async Task A_successful_issuance_needs_no_challenge_handling()
    {
        using var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = JsonContent.Create(SampleGrant()),
        });
        using var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://control.mina.example/") };
        var tokenProvider = new RecordingReceiver();
        var client = new ControlPlaneClient(httpClient, tokenProvider);

        var grant = await client.IssueAsync("westeurope", [1, 2, 3], CancellationToken.None);

        Assert.Equal("westeurope", grant.Region);
        Assert.Empty(tokenProvider.RecordedChallenges);
    }

    [Fact]
    public async Task An_insufficient_claims_challenge_is_decoded_and_handed_to_the_token_provider()
    {
        var encoded = EncodeChallenge("c1");
        using var handler = new StubHandler(_ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
            response.Headers.TryAddWithoutValidation(
                "WWW-Authenticate", $"Bearer error=\"insufficient_claims\", claims=\"{encoded}\"");
            return response;
        });
        using var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://control.mina.example/") };
        var tokenProvider = new RecordingReceiver();
        var client = new ControlPlaneClient(httpClient, tokenProvider);

        var ex = await Assert.ThrowsAsync<ControlPlaneException>(
            () => client.IssueAsync("westeurope", [1, 2, 3], CancellationToken.None));

        Assert.Equal(HttpStatusCode.Unauthorized, ex.StatusCode);
        var recorded = Assert.Single(tokenProvider.RecordedChallenges);
        Assert.Equal("""{"access_token":{"acrs":{"essential":true,"value":"c1"}}}""", recorded);
    }

    [Fact]
    public async Task The_same_challenge_handling_applies_to_renewal()
    {
        var encoded = EncodeChallenge("c1");
        using var handler = new StubHandler(_ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
            response.Headers.TryAddWithoutValidation(
                "WWW-Authenticate", $"Bearer error=\"insufficient_claims\", claims=\"{encoded}\"");
            return response;
        });
        using var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://control.mina.example/") };
        var tokenProvider = new RecordingReceiver();
        var client = new ControlPlaneClient(httpClient, tokenProvider);

        await Assert.ThrowsAsync<ControlPlaneException>(
            () => client.RenewAsync(Guid.NewGuid(), [1, 2, 3], CancellationToken.None));

        Assert.Single(tokenProvider.RecordedChallenges);
    }

    [Fact]
    public async Task An_ordinary_unauthorized_response_is_not_mistaken_for_a_claims_challenge()
    {
        // No WWW-Authenticate at all -- e.g. a plain expired/invalid-token 401. Must not be
        // misread as something MSAL's .WithClaims(...) could resolve.
        using var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.Unauthorized));
        using var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://control.mina.example/") };
        var tokenProvider = new RecordingReceiver();
        var client = new ControlPlaneClient(httpClient, tokenProvider);

        var ex = await Assert.ThrowsAsync<ControlPlaneException>(
            () => client.IssueAsync("westeurope", [1, 2, 3], CancellationToken.None));

        Assert.Equal(HttpStatusCode.Unauthorized, ex.StatusCode);
        Assert.Empty(tokenProvider.RecordedChallenges);
    }

    [Fact]
    public async Task A_provider_that_cannot_act_on_a_challenge_still_gets_a_clean_refusal()
    {
        // ConfiguredAccessTokenProvider (dev/test) does not implement IClaimsChallengeReceiver.
        // The challenge must still surface as an ordinary refusal rather than throwing from inside
        // the parsing/dispatch itself.
        var encoded = EncodeChallenge("c1");
        using var handler = new StubHandler(_ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
            response.Headers.TryAddWithoutValidation(
                "WWW-Authenticate", $"Bearer error=\"insufficient_claims\", claims=\"{encoded}\"");
            return response;
        });
        using var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://control.mina.example/") };
        var client = new ControlPlaneClient(httpClient, new ConfiguredAccessTokenProvider("test-token"));

        var ex = await Assert.ThrowsAsync<ControlPlaneException>(
            () => client.IssueAsync("westeurope", [1, 2, 3], CancellationToken.None));

        Assert.Equal(HttpStatusCode.Unauthorized, ex.StatusCode);
    }

    private static object SampleGrant() => new
    {
        sessionId = Guid.NewGuid(),
        certificatePem = "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----",
        certificateSerialNumber = "01",
        region = "westeurope",
        egressHost = "egress.example",
        egressPort = 443,
        egressServerName = "egress.example",
        leaseExpiresAt = DateTimeOffset.UtcNow.AddMinutes(60),
        mode = "Normal",
    };

    private sealed class RecordingReceiver : IAccessTokenProvider, IClaimsChallengeReceiver
    {
        public List<string> RecordedChallenges { get; } = [];

        public Task<string> GetAccessTokenAsync(CancellationToken cancellationToken) =>
            Task.FromResult("test-token");

        public void RecordClaimsChallenge(string claimsChallenge) => RecordedChallenges.Add(claimsChallenge);
    }

    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(respond(request));
    }
}
