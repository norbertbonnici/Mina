using System.Globalization;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Mina.EndpointAgent.Configuration;
using Mina.EndpointAgent.Ipc;
using Mina.EndpointAgent.Tray;

namespace Mina.EndpointAgent.Tests;

/// <summary>
/// The tray's half of the M2-4 session-0 workaround, over a real pipe: acquiring silently, only
/// when actually needed, and re-acquiring on a claims challenge (ARCHITECTURE §3.1/§4).
/// </summary>
[Collection(TrayIpcCollectionMarker.Name)]
public sealed class TokenRelayServiceTests : IAsyncLifetime, IAsyncDisposable
{
    private static readonly DateTimeOffset Start = new(2026, 9, 1, 14, 0, 0, TimeSpan.Zero);

    private readonly RecordingTrayControl _control = new();
    private readonly MutableTimeProvider _clock = new(Start);
    private readonly FakeTokenAcquirer _acquirer = new();
    private readonly string _pipeName =
        "mina-vm-" + Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture);

    private bool _disposed;
    private TrayIpcServer _server = null!;
    private TrayIpcClient _client = null!;
    private TokenRelayService _relay = null!;

    public async Task InitializeAsync()
    {
        _server = new TrayIpcServer(
            _control, Options.Create(new MinaAgentOptions()), NullLogger<TrayIpcServer>.Instance)
        {
            PipeName = _pipeName,
        };
        await _server.StartAsync(CancellationToken.None);
        await WaitForPipeReadyAsync(_pipeName);

        _client = new TrayIpcClient(_pipeName);
        _relay = new TokenRelayService(_acquirer, _client, _clock);
    }

    private static async Task WaitForPipeReadyAsync(string pipeName)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        while (true)
        {
            await using var probe = new System.IO.Pipes.NamedPipeClientStream(
                ".", pipeName, System.IO.Pipes.PipeDirection.InOut, System.IO.Pipes.PipeOptions.Asynchronous);
            try
            {
                await probe.ConnectAsync(500, deadline.Token);
                return;
            }
            catch (Exception ex) when (ex is IOException or TimeoutException or OperationCanceledException)
            {
                if (deadline.IsCancellationRequested)
                {
                    throw;
                }
            }
        }
    }

    Task IAsyncLifetime.DisposeAsync() => TearDownAsync().AsTask();

    ValueTask IAsyncDisposable.DisposeAsync() => TearDownAsync();

    private async ValueTask TearDownAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        await _client.DisposeAsync();
        await _server.StopAsync(CancellationToken.None);
        _server.Dispose();
    }

    [Fact]
    public async Task A_first_call_with_no_prior_token_acquires_and_submits()
    {
        _acquirer.NextResult = TokenAcquisitionResult.Success("token-1", Start.AddMinutes(60));

        var submitted = await _relay.EnsureFreshTokenAsync(requiredClaims: null, CancellationToken.None);

        Assert.True(submitted);
        Assert.Equal(1, _acquirer.CallCount);
        var request = Assert.Single(_control.Seen);
        Assert.Equal(TrayOperations.SubmitAccessToken, request.Op);
        Assert.Equal("token-1", request.AccessToken);
    }

    [Fact]
    public async Task A_still_fresh_token_is_not_reacquired()
    {
        _acquirer.NextResult = TokenAcquisitionResult.Success("token-1", Start.AddMinutes(60));
        await _relay.EnsureFreshTokenAsync(requiredClaims: null, CancellationToken.None);

        var submitted = await _relay.EnsureFreshTokenAsync(requiredClaims: null, CancellationToken.None);

        Assert.False(submitted);
        Assert.Equal(1, _acquirer.CallCount);
    }

    [Fact]
    public async Task A_token_nearing_expiry_is_refreshed()
    {
        _acquirer.NextResult = TokenAcquisitionResult.Success("token-1", Start.AddMinutes(60));
        await _relay.EnsureFreshTokenAsync(requiredClaims: null, CancellationToken.None);

        _clock.Advance(TimeSpan.FromMinutes(51));
        _acquirer.NextResult = TokenAcquisitionResult.Success("token-2", Start.AddMinutes(120));

        var submitted = await _relay.EnsureFreshTokenAsync(requiredClaims: null, CancellationToken.None);

        Assert.True(submitted);
        Assert.Equal(2, _acquirer.CallCount);
        Assert.Equal("token-2", _control.Seen[^1].AccessToken);
    }

    [Fact]
    public async Task A_new_claims_challenge_forces_reacquisition_even_with_a_fresh_token()
    {
        _acquirer.NextResult = TokenAcquisitionResult.Success("token-1", Start.AddMinutes(60));
        await _relay.EnsureFreshTokenAsync(requiredClaims: null, CancellationToken.None);

        const string claims = """{"access_token":{"acrs":{"essential":true,"value":"c1"}}}""";
        _acquirer.NextResult = TokenAcquisitionResult.Success("token-stepped-up", Start.AddMinutes(60));

        var submitted = await _relay.EnsureFreshTokenAsync(claims, CancellationToken.None);

        Assert.True(submitted);
        Assert.Equal(2, _acquirer.CallCount);
        Assert.Equal(claims, _acquirer.LastClaimsRequested);
        Assert.Equal("token-stepped-up", _control.Seen[^1].AccessToken);
    }

    [Fact]
    public async Task The_same_claims_challenge_is_not_reapplied_once_satisfied()
    {
        const string claims = """{"access_token":{"acrs":{"essential":true,"value":"c1"}}}""";
        _acquirer.NextResult = TokenAcquisitionResult.Success("token-stepped-up", Start.AddMinutes(60));
        await _relay.EnsureFreshTokenAsync(claims, CancellationToken.None);

        var submitted = await _relay.EnsureFreshTokenAsync(claims, CancellationToken.None);

        Assert.False(submitted);
        Assert.Equal(1, _acquirer.CallCount);
    }

    [Fact]
    public async Task An_acquisition_failure_is_reported_and_nothing_is_submitted()
    {
        _acquirer.NextResult = TokenAcquisitionResult.Failure("silent sign-in failed, no cached account");

        var submitted = await _relay.EnsureFreshTokenAsync(requiredClaims: null, CancellationToken.None);

        Assert.False(submitted);
        Assert.Empty(_control.Seen);
        Assert.Equal("silent sign-in failed, no cached account", _relay.LastFailureReason);
    }

    [Fact]
    public async Task An_agent_refusal_of_the_token_is_retried_on_the_next_call()
    {
        _control.Respond = request => request.Op == TrayOperations.SubmitAccessToken
            ? TrayResponse.Failure(TrayErrorCodes.InvalidRequest, "no thanks")
            : TrayResponse.Success(new AgentStatusDto { State = ProtectedPathStates.Connecting });
        _acquirer.NextResult = TokenAcquisitionResult.Success("token-1", Start.AddMinutes(60));

        var submitted = await _relay.EnsureFreshTokenAsync(requiredClaims: null, CancellationToken.None);
        Assert.False(submitted);
        Assert.Equal("no thanks", _relay.LastFailureReason);

        // Nothing was recorded as applied, so the very next call tries again rather than treating
        // the refused token as though it were live.
        _control.Respond = null;
        var retried = await _relay.EnsureFreshTokenAsync(requiredClaims: null, CancellationToken.None);

        Assert.True(retried);
        Assert.Equal(2, _acquirer.CallCount);
    }

    private sealed class FakeTokenAcquirer : IEntraTokenAcquirer
    {
        public TokenAcquisitionResult NextResult { get; set; } = TokenAcquisitionResult.Failure("not configured");

        public int CallCount { get; private set; }

        public string? LastClaimsRequested { get; private set; }

        public Task<TokenAcquisitionResult> AcquireAsync(string? claimsChallenge, CancellationToken cancellationToken)
        {
            CallCount++;
            LastClaimsRequested = claimsChallenge;
            return Task.FromResult(NextResult);
        }
    }
}
