using System.Windows;
using System.Windows.Threading;
using Mina.EndpointAgent.Ipc;

namespace Mina.EndpointAgent.Tray;

/// <summary>
/// The tray process. It owns a notification-area icon, one flyout, and a timer — and it holds no
/// authority of its own: everything it can do, it does by asking the agent over the named pipe.
/// </summary>
/// <remarks>
/// Closing this process removes the analyst's indicator and nothing else. Enforcement lives in the
/// agent — the firewall rules bound to the research browser, and the fact that the loopback proxy
/// does not listen without a session — so a tray that is killed, tampered with, or never started
/// cannot open a path that would otherwise be closed.
/// </remarks>
public sealed partial class App : Application, IDisposable
{
    /// <summary>Poll cadence while the analyst is looking at the panel.</summary>
    private const int VisiblePollSeconds = 2;

    /// <summary>Poll cadence when only the icon is on screen.</summary>
    private const int HiddenPollSeconds = 5;

    private Mutex? _instanceLock;
    private TrayViewModel? _viewModel;
    private TrayIconHost? _icon;
    private TrayPanelWindow? _panel;
    private DispatcherTimer? _timer;
    private int _ticks;
    private bool _disposed;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // One tray per logon session. A second instance would double the polling and give the
        // analyst two panels that disagree while one of them is mid-refresh.
        _instanceLock = new Mutex(initiallyOwned: true, @"Local\Mina.Tray", out var isOnlyInstance);
        if (!isOnlyInstance)
        {
            Shutdown();
            return;
        }

        _viewModel = new TrayViewModel(new TrayIpcClient(), TimeProvider.System);
        _panel = new TrayPanelWindow(_viewModel, AskForSensitiveRequest);

        _icon = new TrayIconHost();
        _icon.Opened += (_, _) => TogglePanel();
        _icon.Exited += (_, _) => Shutdown();
        _icon.Update(_viewModel.Panel);

        _timer = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromSeconds(1) };
        _timer.Tick += OnTick;
        _timer.Start();
    }

    private void TogglePanel()
    {
        if (_panel is null)
        {
            return;
        }

        if (_panel.IsVisible)
        {
            _panel.Hide();
            return;
        }

        _panel.ShowAtTray();

        // Show the freshest reading rather than whatever the last background poll left behind.
        _ = RefreshAsync();
    }

    private async void OnTick(object? sender, EventArgs e)
    {
        if (_viewModel is null)
        {
            return;
        }

        _ticks++;
        var cadence = _panel is { IsVisible: true } ? VisiblePollSeconds : HiddenPollSeconds;

        if (_ticks % cadence == 0)
        {
            await RefreshAsync();
        }
        else
        {
            // Between polls, move the countdowns from the reading already held. No pipe call, and
            // so no control-plane call, once a second.
            _viewModel.Tick();
        }

        _icon?.Update(_viewModel.Panel);
    }

    private async Task RefreshAsync()
    {
        if (_viewModel is null)
        {
            return;
        }

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        await _viewModel.RefreshAsync(timeout.Token);
        _icon?.Update(_viewModel.Panel);
    }

    private SensitiveRequest? AskForSensitiveRequest()
    {
        if (_panel is null || _viewModel is null)
        {
            return null;
        }

        var dialog = new SensitiveRequestWindow(_viewModel.MaxSensitiveMinutes) { Owner = _panel };

        _panel.SuppressAutoHide = true;
        try
        {
            return dialog.ShowDialog() == true ? dialog.Request : null;
        }
        finally
        {
            _panel.SuppressAutoHide = false;
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        Dispose();
        base.OnExit(e);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _timer?.Stop();
        _icon?.Dispose();

        if (_viewModel is not null)
        {
            // The process is going away; blocking briefly on the pipe teardown is preferable to
            // leaving the agent holding a half-closed instance.
            _viewModel.DisposeAsync().AsTask().GetAwaiter().GetResult();
        }

        _instanceLock?.Dispose();
    }
}
