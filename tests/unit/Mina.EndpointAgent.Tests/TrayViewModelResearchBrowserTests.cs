using System.Globalization;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Mina.EndpointAgent.Configuration;
using Mina.EndpointAgent.Ipc;
using Mina.EndpointAgent.Tray;

namespace Mina.EndpointAgent.Tests;

/// <summary>
/// The view model's side of launching the research browser (M2-4): a local action, not a pipe
/// request, but still governed entirely by what the agent's status says — the same discipline as
/// every other command in <see cref="TrayViewModel"/>.
/// </summary>
[Collection(TrayIpcCollectionMarker.Name)]
public sealed class TrayViewModelResearchBrowserTests : IAsyncLifetime, IAsyncDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 9, 1, 14, 0, 0, TimeSpan.Zero);

    private readonly RecordingTrayControl _control = new();
    private readonly MutableTimeProvider _clock = new(Now);
    private readonly SpyProcessLauncher _processLauncher = new();
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
        await WaitForPipeReadyAsync(_pipeName);

        var template = new ResearchBrowserLaunchTemplate(
            "msedge.exe", ["--user-data-dir={ResearchProfileDir}", "--proxy-server=http://127.0.0.1:{AgentProxyPort}"]);
        var launcher = new ResearchBrowserLauncher(template, @"C:\Mina\ResearchProfile", _processLauncher);
        _viewModel = new TrayViewModel(new TrayIpcClient(_pipeName), _clock, launcher);
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
        await _viewModel.DisposeAsync();
        await _server.StopAsync(CancellationToken.None);
        _server.Dispose();
    }

    [Fact]
    public async Task A_configured_launcher_is_reported_as_available()
    {
        await _viewModel.RefreshAsync(CancellationToken.None);

        Assert.True(_viewModel.HasResearchBrowserLauncher);
    }

    [Fact]
    public async Task Launching_while_protected_starts_the_browser_pinned_to_the_live_port()
    {
        _control.Respond = _ => TrayResponse.Success(new AgentStatusDto
        {
            State = ProtectedPathStates.Protected,
            ProxyPort = 54219,
        });
        await _viewModel.RefreshAsync(CancellationToken.None);

        _viewModel.LaunchResearchBrowser();

        Assert.Equal("msedge.exe", _processLauncher.FileName);
        Assert.Equal(
            ["--user-data-dir=C:\\Mina\\ResearchProfile", "--proxy-server=http://127.0.0.1:54219"],
            _processLauncher.Arguments);
    }

    [Fact]
    public async Task Launching_without_a_live_session_does_nothing()
    {
        _control.Respond = _ => TrayResponse.Success(new AgentStatusDto { State = ProtectedPathStates.Stopped });
        await _viewModel.RefreshAsync(CancellationToken.None);

        _viewModel.LaunchResearchBrowser();

        Assert.Null(_processLauncher.FileName);
    }

    [Fact]
    public async Task Launching_before_any_status_is_known_does_nothing()
    {
        // No RefreshAsync yet -- exactly the state right after the tray starts.
        await Task.CompletedTask;

        _viewModel.LaunchResearchBrowser();

        Assert.Null(_processLauncher.FileName);
    }

    private sealed class SpyProcessLauncher : IProcessLauncher
    {
        public string? FileName { get; private set; }

        public IReadOnlyList<string> Arguments { get; private set; } = [];

        public void Start(string fileName, IReadOnlyList<string> arguments)
        {
            FileName = fileName;
            Arguments = arguments;
        }
    }
}
