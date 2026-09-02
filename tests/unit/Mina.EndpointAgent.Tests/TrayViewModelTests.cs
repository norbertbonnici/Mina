using System.Globalization;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Mina.EndpointAgent.Configuration;
using Mina.EndpointAgent.Ipc;
using Mina.EndpointAgent.Tray;

namespace Mina.EndpointAgent.Tests;

/// <summary>
/// The tray end to end over a real pipe: client, server and the model the WPF shell binds to. What
/// these pin down is that the panel never states a protection the agent did not report.
/// </summary>
public sealed class TrayViewModelTests : IAsyncLifetime, IAsyncDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 9, 1, 14, 0, 0, TimeSpan.Zero);

    private readonly RecordingTrayControl _control = new();
    private readonly MutableTimeProvider _clock = new(Now);
    private readonly string _pipeName =
        "mina-vm-" + Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture);

    private bool _disposed;
    private TrayIpcServer _server = null!;
    private TrayViewModel _viewModel = null!;

    public async Task InitializeAsync()
    {
        _server = new TrayIpcServer(
            _control, Options.Create(new MinaAgentOptions()), NullLogger<TrayIpcServer>.Instance)
        {
            PipeName = _pipeName,
        };

        await _server.StartAsync(CancellationToken.None);

        // Absorb a slow first accept (this server was just started, and CI's Windows runner can be
        // slow to schedule it) here, at a raw pipe level that never touches _control — a warm-up
        // through the real client would count as a request and break the exact-call-count and
        // exact-sequence assertions later in this file (Assert.Single(_control.Seen) and similar).
        // The real client below keeps the untouched production connect timeout throughout, which
        // An_agent_that_stops_answering_is_reported_as_unavailable depends on for its own timing.
        await WaitForPipeReadyAsync(_pipeName);
        _viewModel = new TrayViewModel(new TrayIpcClient(_pipeName), _clock);
    }

    private static async Task WaitForPipeReadyAsync(string pipeName)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
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

    // Explicit on both interfaces: xunit's IAsyncLifetime.DisposeAsync returns Task and cannot also
    // satisfy IAsyncDisposable, which the analyzers want on a type holding disposable fields.
    Task IAsyncLifetime.DisposeAsync() => TearDownAsync().AsTask();

    ValueTask IAsyncDisposable.DisposeAsync() => TearDownAsync();

    private async ValueTask TearDownAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        await _viewModel.DisposeAsync();
        await _server.StopAsync(CancellationToken.None);
        _server.Dispose();
    }

    [Fact]
    public async Task Refreshing_adopts_what_the_agent_reported()
    {
        _control.Respond = _ => TrayResponse.Success(new AgentStatusDto
        {
            State = ProtectedPathStates.Protected,
            Region = "francecentral",
            Mode = "Normal",
        });

        await _viewModel.RefreshAsync(CancellationToken.None);

        Assert.Equal("Protected", _viewModel.Panel.Headline);
        Assert.Contains("France Central", _viewModel.Panel.Detail, StringComparison.Ordinal);
        Assert.True(_viewModel.IsConnected);
    }

    [Fact]
    public async Task A_refusal_shows_the_reason_over_the_status_that_came_with_it()
    {
        _control.Respond = request => request.Op == TrayOperations.SelectRegion
            ? TrayResponse.Failure(
                TrayErrorCodes.RegionNotSelectable,
                "That region is not available to you. Choose one from the list.",
                new AgentStatusDto { State = ProtectedPathStates.Protected, Region = "westeurope" })
            : TrayResponse.Success(new AgentStatusDto { State = ProtectedPathStates.Protected });

        await _viewModel.SelectRegionAsync("eastus", CancellationToken.None);

        Assert.Equal("That region is not available to you. Choose one from the list.", _viewModel.Panel.Notice);
        Assert.Equal("Protected", _viewModel.Panel.Headline);
    }

    [Fact]
    public async Task A_notice_clears_on_the_next_successful_action()
    {
        _control.Respond = _ => TrayResponse.Failure(
            TrayErrorCodes.InvalidRequest, "No.", new AgentStatusDto { State = ProtectedPathStates.Protected });
        await _viewModel.RefreshAsync(CancellationToken.None);
        Assert.NotNull(_viewModel.Panel.Notice);

        _control.Respond = _ => TrayResponse.Success(new AgentStatusDto { State = ProtectedPathStates.Protected });
        await _viewModel.RefreshAsync(CancellationToken.None);

        Assert.Null(_viewModel.Panel.Notice);
    }

    [Fact]
    public async Task An_agent_that_stops_answering_is_reported_as_unavailable()
    {
        await _viewModel.RefreshAsync(CancellationToken.None);
        Assert.True(_viewModel.IsConnected);

        await _server.StopAsync(CancellationToken.None);
        await _viewModel.RefreshAsync(CancellationToken.None);

        Assert.False(_viewModel.IsConnected);
        Assert.Equal("Agent unavailable", _viewModel.Panel.Headline);

        // Still the fail-closed message: an unreachable agent is not a reason to think traffic went
        // out the ordinary way.
        Assert.Contains("Nothing has moved", _viewModel.Panel.Alert, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Countdowns_move_between_polls_without_asking_the_agent()
    {
        _control.Respond = _ => TrayResponse.Success(new AgentStatusDto
        {
            State = ProtectedPathStates.Protected,
            SessionId = Guid.Parse("4f2a91c7-0000-0000-0000-000000000000"),
            LeaseExpiresAt = Now.AddMinutes(5),
        });

        await _viewModel.RefreshAsync(CancellationToken.None);
        Assert.Equal("4f2a91c7 · lease ends in 5:00", _viewModel.Panel.SessionLine);

        _clock.Advance(TimeSpan.FromSeconds(48));
        _viewModel.Tick();

        Assert.Equal("4f2a91c7 · lease ends in 4:12", _viewModel.Panel.SessionLine);
        Assert.Single(_control.Seen);
    }

    [Fact]
    public async Task Every_command_goes_to_the_agent_rather_than_being_applied_locally()
    {
        await _viewModel.EndSessionAsync(CancellationToken.None);
        await _viewModel.StartSessionAsync(CancellationToken.None);
        await _viewModel.RequestSensitiveAsync("CASE-2026-0417", 60, CancellationToken.None);
        await _viewModel.ActivateSensitiveAsync(CancellationToken.None);
        await _viewModel.CancelSensitiveAsync(CancellationToken.None);

        Assert.Equal(
            [
                TrayOperations.EndSession,
                TrayOperations.Reconnect,
                TrayOperations.RequestSensitive,
                TrayOperations.ActivateSensitive,
                TrayOperations.CancelSensitive,
            ],
            _control.Seen.Select(r => r.Op));
    }

    [Fact]
    public async Task The_panel_raises_a_change_notification_the_shell_can_bind_to()
    {
        var raised = 0;
        _viewModel.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(TrayViewModel.Panel))
            {
                raised++;
            }
        };

        await _viewModel.RefreshAsync(CancellationToken.None);

        Assert.True(raised > 0);
    }
}
