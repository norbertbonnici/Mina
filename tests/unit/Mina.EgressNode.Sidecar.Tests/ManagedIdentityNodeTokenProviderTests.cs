using Azure.Core;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Mina.EgressNode.Sidecar;

namespace Mina.EgressNode.Sidecar.Tests;

public class ManagedIdentityNodeTokenProviderTests
{
    private const string Scope = "api://control-plane/.default";

    [Fact]
    public async Task Fetches_a_token_on_first_call()
    {
        var credential = new FakeTokenCredential(TimeSpan.FromMinutes(60));
        var provider = Create(credential, out _);

        var token = await provider.GetTokenAsync(CancellationToken.None);

        Assert.Equal(credential.Tokens[0], token);
        Assert.Equal(1, credential.CallCount);
    }

    [Fact]
    public async Task Reuses_a_cached_token_well_before_expiry()
    {
        var clock = new TestClock(DateTimeOffset.UtcNow);
        var credential = new FakeTokenCredential(TimeSpan.FromMinutes(60), clock);
        var provider = Create(credential, out _, clock);

        var first = await provider.GetTokenAsync(CancellationToken.None);
        clock.Now += TimeSpan.FromMinutes(10);
        var second = await provider.GetTokenAsync(CancellationToken.None);

        Assert.Equal(first, second);
        Assert.Equal(1, credential.CallCount);
    }

    [Fact]
    public async Task Refreshes_once_the_cached_token_enters_the_refresh_window()
    {
        var clock = new TestClock(DateTimeOffset.UtcNow);
        var credential = new FakeTokenCredential(TimeSpan.FromMinutes(60), clock);
        var provider = Create(credential, out _, clock);

        var first = await provider.GetTokenAsync(CancellationToken.None);
        // 5 minutes of headroom before expiry (ManagedIdentityNodeTokenProvider.RefreshBeforeExpiry) --
        // 56 minutes in is inside that window for a 60-minute token.
        clock.Now += TimeSpan.FromMinutes(56);
        var second = await provider.GetTokenAsync(CancellationToken.None);

        Assert.NotEqual(first, second);
        Assert.Equal(2, credential.CallCount);
    }

    [Fact]
    public async Task Requests_the_configured_scope()
    {
        var credential = new FakeTokenCredential(TimeSpan.FromMinutes(60));
        var provider = Create(credential, out _);

        await provider.GetTokenAsync(CancellationToken.None);

        var requested = Assert.Single(credential.RequestedScopes);
        Assert.Equal([Scope], requested);
    }

    [Fact]
    public async Task Concurrent_callers_during_a_refresh_share_one_credential_call()
    {
        var clock = new TestClock(DateTimeOffset.UtcNow);
        var credential = new FakeTokenCredential(TimeSpan.FromMinutes(60), clock);
        var provider = Create(credential, out _, clock);
        await provider.GetTokenAsync(CancellationToken.None); // primes the cache, call #1
        clock.Now += TimeSpan.FromMinutes(56); // inside the refresh window

        credential.PauseNextCall();
        var callers = Enumerable.Range(0, 8)
            .Select(_ => provider.GetTokenAsync(CancellationToken.None))
            .ToArray();
        await Task.Delay(50); // let every caller reach the lock/fast-path check before unblocking
        credential.ResumeNextCall();
        var results = await Task.WhenAll(callers);

        Assert.Equal(2, credential.CallCount); // the initial prime, plus exactly one refresh
        Assert.All(results, r => Assert.Equal(results[0], r));
    }

    [Fact]
    public async Task Propagates_credential_failures_without_caching_anything()
    {
        var credential = new FakeTokenCredential(TimeSpan.FromMinutes(60)) { ThrowOnNextCall = true };
        var provider = Create(credential, out _);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => provider.GetTokenAsync(CancellationToken.None));

        // A subsequent, non-failing call must still try the credential rather than serve a bad cache.
        credential.ThrowOnNextCall = false;
        var token = await provider.GetTokenAsync(CancellationToken.None);
        Assert.Equal(credential.Tokens[0], token);
    }

    [Fact]
    public void Constructor_rejects_null_or_empty_arguments()
    {
        var credential = new FakeTokenCredential(TimeSpan.FromMinutes(60));
        var logger = NullLogger<ManagedIdentityNodeTokenProvider>.Instance;

        Assert.Throws<ArgumentNullException>(() =>
            new ManagedIdentityNodeTokenProvider(null!, Scope, TimeProvider.System, logger));
        Assert.Throws<ArgumentException>(() =>
            new ManagedIdentityNodeTokenProvider(credential, "", TimeProvider.System, logger));
        Assert.Throws<ArgumentNullException>(() =>
            new ManagedIdentityNodeTokenProvider(credential, Scope, null!, logger));
        Assert.Throws<ArgumentNullException>(() =>
            new ManagedIdentityNodeTokenProvider(credential, Scope, TimeProvider.System, null!));
    }

    private static ManagedIdentityNodeTokenProvider Create(
        FakeTokenCredential credential, out ILogger<ManagedIdentityNodeTokenProvider> logger, TimeProvider? clock = null)
    {
        logger = NullLogger<ManagedIdentityNodeTokenProvider>.Instance;
        return new ManagedIdentityNodeTokenProvider(credential, Scope, clock ?? TimeProvider.System, logger);
    }

    /// <summary>
    /// Hand-rolled fake, matching this project's no-mocking-framework test convention. Issues a
    /// new token string on every real call so tests can tell "reused the cache" from "fetched
    /// again" by equality alone.
    /// </summary>
    private sealed class FakeTokenCredential(TimeSpan tokenLifetime, TimeProvider? clock = null) : TokenCredential
    {
        // Must share the same clock the provider reasons about expiry with -- a real-wall-clock
        // expiry stays "60 minutes from now" in real time regardless of how far a TestClock has
        // been fast-forwarded, so a freshly issued token would look instantly stale the moment the
        // test clock is more than a few seconds ahead of the real clock.
        private readonly TimeProvider _clock = clock ?? TimeProvider.System;
        private readonly List<string> _tokens = [];
        private readonly List<string[]> _requestedScopes = [];
        private TaskCompletionSource? _gate;

        public List<string> Tokens => _tokens;
        public List<string[]> RequestedScopes => _requestedScopes;
        public int CallCount => _tokens.Count;
        public bool ThrowOnNextCall { get; set; }

        public void PauseNextCall() => _gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        public void ResumeNextCall() => _gate?.TrySetResult();

        public override async ValueTask<AccessToken> GetTokenAsync(
            TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            if (_gate is { } gate)
            {
                await gate.Task.ConfigureAwait(false);
                _gate = null;
            }

            _requestedScopes.Add(requestContext.Scopes);

            if (ThrowOnNextCall)
            {
                ThrowOnNextCall = false;
                throw new InvalidOperationException("simulated managed-identity failure");
            }

            var token = $"token-{_tokens.Count}";
            _tokens.Add(token);
            return new AccessToken(token, _clock.GetUtcNow().Add(tokenLifetime));
        }

        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            throw new NotSupportedException("Only the async path is exercised by this sidecar.");
    }
}
