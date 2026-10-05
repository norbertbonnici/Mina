using System.IO;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Threading;
using Microsoft.Extensions.Configuration;
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
    private TrayIpcClient? _tokenIpcClient;
    private TokenRelayService? _tokenRelay;
    private Task? _tokenRelayTask;
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

        var options = LoadTrayOptions();
        _viewModel = new TrayViewModel(new TrayIpcClient(), TimeProvider.System, TryCreateResearchBrowserLauncher(options));
        _panel = new TrayPanelWindow(_viewModel, AskForSensitiveRequest);

        _icon = new TrayIconHost();
        _icon.Opened += (_, _) => TogglePanel();
        _icon.Exited += (_, _) => Shutdown();
        _icon.Update(_viewModel.Panel);

        _tokenRelay = TryCreateTokenRelay(options);

        _timer = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromSeconds(1) };
        _timer.Tick += OnTick;
        _timer.Start();
    }

    private static TrayOptions LoadTrayOptions()
    {
        var configuration = new ConfigurationBuilder()
            .SetBasePath(AppContext.BaseDirectory)
            .AddJsonFile("appsettings.json", optional: true)
            .Build();

        return configuration.GetSection(TrayOptions.Section).Get<TrayOptions>() ?? new TrayOptions();
    }

    /// <summary>
    /// Builds the M2-4 sign-in relay, over its own pipe connection (the server accepts several at
    /// once; keeping this separate from the view model's own client means a slow token acquisition
    /// never blocks a status poll or vice versa). Returns null rather than throwing when the
    /// tenant/client id are missing or still carry the checked-in template's placeholders (M2-5's
    /// packaging, which delivers the real deployment values, has not landed yet) — the tray still
    /// shows the agent's status without it, just with the agent permanently reporting "waiting for
    /// sign-in", which is the correct, visible, fail-closed outcome rather than a WPF app that
    /// crashes on launch in an unconfigured environment.
    /// </summary>
    private TokenRelayService? TryCreateTokenRelay(TrayOptions options)
    {
        if (!Guid.TryParse(options.ClientId, out _) || !Guid.TryParse(options.TenantId, out _))
        {
            return null;
        }

        var acquirer = new WamTokenAcquirer(options, GetPanelWindowHandle);
        _tokenIpcClient = new TrayIpcClient();
        return new TokenRelayService(acquirer, _tokenIpcClient, TimeProvider.System);
    }

    /// <summary>
    /// Builds the M2-4 research-browser launcher from the copy of
    /// <c>edge-integration/research-browser-flags.json</c> this project's own build copies
    /// alongside it. Returns null — same reasoning as <see cref="TryCreateTokenRelay"/> — when the
    /// profile directory is unconfigured or the flags file is missing or malformed, rather than
    /// crashing the tray over what M2-5's packaging has not supplied yet.
    /// </summary>
    private static ResearchBrowserLauncher? TryCreateResearchBrowserLauncher(TrayOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.ResearchProfileDirectory))
        {
            return null;
        }

        var flagsPath = Path.Combine(AppContext.BaseDirectory, "research-browser-flags.json");
        try
        {
            var template = ResearchBrowserLaunchTemplate.Parse(File.ReadAllText(flagsPath));
            return new ResearchBrowserLauncher(template, options.ResearchProfileDirectory, new RealProcessLauncher());
        }
        catch (Exception ex) when (ex is IOException or FormatException)
        {
            return null;
        }
    }

    /// <summary>
    /// The window WAM's interactive prompt parents to. This is deliberately the panel window
    /// itself, not <see cref="Application.MainWindow"/>: WPF only assigns that automatically to the
    /// first window actually <c>Show()</c>n, and the panel usually is not visible yet the first
    /// time a sign-in prompt can happen (the analyst has not opened it). <c>EnsureHandle()</c>
    /// forces the underlying HWND to exist regardless of visibility, which a plain <c>.Handle</c>
    /// read would not guarantee.
    /// </summary>
    private IntPtr GetPanelWindowHandle() =>
        _panel is { } panel ? new WindowInteropHelper(panel).EnsureHandle() : IntPtr.Zero;

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

        // Fire-and-forget, deliberately: an interactive WAM prompt (first sign-in, or a claims
        // step-up) can take far longer than a status poll's own budget, and awaiting it here would
        // freeze the panel's regular refresh for however long the analyst takes to sign in.
        TriggerTokenRelay(_viewModel.RequiredClaims);
    }

    /// <summary>
    /// Starts one token-relay attempt if none is already running. Guarding against overlap matters
    /// specifically because this can go interactive: without it, a poll every one to five seconds
    /// could stack up several WAM prompts on top of one another.
    /// </summary>
    private void TriggerTokenRelay(string? requiredClaims)
    {
        if (_tokenRelay is null || (_tokenRelayTask is { IsCompleted: false }))
        {
            return;
        }

        // A generous ceiling for an interactive sign-in the analyst has to actually complete, not
        // the tight budget a status poll uses -- cancelled here only so a truly abandoned prompt
        // does not pin this task forever, never as a normal-path timeout.
        var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(5));
        _tokenRelayTask = RunTokenRelayAsync(_tokenRelay, requiredClaims, timeout.Token)
            .ContinueWith(_ => timeout.Dispose(), TaskScheduler.Default);
    }

    /// <summary>
    /// Every exception is swallowed here on purpose: this runs detached from the caller (see
    /// <see cref="TriggerTokenRelay"/>), so nothing catches what escapes it, and the alternative to
    /// swallowing is an unobserved-task-exception crash unrelated to whatever the analyst is doing
    /// at the time. A failed acquisition already surfaces to the analyst through the ordinary
    /// route: the agent keeps reporting "waiting for sign-in" until one actually lands.
    /// </summary>
    private static async Task RunTokenRelayAsync(
        TokenRelayService relay, string? requiredClaims, CancellationToken cancellationToken)
    {
        try
        {
            await relay.EnsureFreshTokenAsync(requiredClaims, cancellationToken);
        }
        catch (Exception)
        {
            // See remarks above.
        }
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

        if (_tokenIpcClient is not null)
        {
            _tokenIpcClient.DisposeAsync().AsTask().GetAwaiter().GetResult();
        }

        _instanceLock?.Dispose();
    }
}
