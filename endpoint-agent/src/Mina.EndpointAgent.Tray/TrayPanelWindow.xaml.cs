using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace Mina.EndpointAgent.Tray;

/// <summary>
/// The flyout the analyst sees. It renders <see cref="TrayViewModel.Panel"/> and nothing else — no
/// local state, no optimistic updates — so the window cannot claim a protection the agent has not
/// reported.
/// </summary>
/// <remarks>
/// Rendering is explicit rather than data-bound. The panel is small, every field is set in one
/// place, and an endpoint component that only gets exercised in the Windows lab is better served by
/// code a reviewer can follow than by binding expressions that fail silently at runtime.
/// </remarks>
public partial class TrayPanelWindow : Window
{
    private readonly TrayViewModel _viewModel;
    private readonly Func<SensitiveRequest?> _askForSensitiveRequest;

    /// <summary>Guards the region box while it is being repopulated from a fresh panel.</summary>
    private bool _rendering;

    public TrayPanelWindow(TrayViewModel viewModel, Func<SensitiveRequest?> askForSensitiveRequest)
    {
        _viewModel = viewModel ?? throw new ArgumentNullException(nameof(viewModel));
        _askForSensitiveRequest = askForSensitiveRequest
                                  ?? throw new ArgumentNullException(nameof(askForSensitiveRequest));

        InitializeComponent();

        CloseButton.Click += (_, _) => Hide();
        LaunchButton.Click += (_, _) => _viewModel.LaunchResearchBrowser();
        StartButton.Click += async (_, _) => await RunAsync(ct => _viewModel.StartSessionAsync(ct));
        RetryButton.Click += async (_, _) => await RunAsync(ct => _viewModel.ReconnectAsync(ct));
        EndButton.Click += async (_, _) => await RunAsync(ct => _viewModel.EndSessionAsync(ct));
        ActivateButton.Click += async (_, _) => await RunAsync(ct => _viewModel.ActivateSensitiveAsync(ct));
        WithdrawButton.Click += async (_, _) => await RunAsync(ct => _viewModel.CancelSensitiveAsync(ct));
        RequestButton.Click += async (_, _) => await RequestSensitiveAsync();
        RegionBox.SelectionChanged += async (_, e) => await RegionChangedAsync(e);

        _viewModel.PropertyChanged += OnViewModelChanged;
        Render(_viewModel.Panel);
    }

    /// <summary>Shows the panel above the notification area and gives it focus.</summary>
    public void ShowAtTray()
    {
        Render(_viewModel.Panel);

        // Measure first: the window is SizeToContent, so ActualHeight is stale until it lays out.
        Show();
        UpdateLayout();

        var work = SystemParameters.WorkArea;
        Left = work.Right - Width - 12;
        Top = work.Bottom - ActualHeight - 12;

        Activate();
        Focus();
    }

    /// <summary>
    /// Held while a modal dialog this window owns is open. Without it, opening the sensitive-session
    /// dialog would deactivate the panel, hide it, and take the dialog's owner out from under it.
    /// </summary>
    public bool SuppressAutoHide { get; set; }

    protected override void OnDeactivated(EventArgs e)
    {
        base.OnDeactivated(e);

        if (SuppressAutoHide)
        {
            return;
        }

        // Behave like a notification-area flyout: clicking elsewhere dismisses it.
        Hide();
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        ArgumentNullException.ThrowIfNull(e);

        // Alt+F4 on a tray flyout should put it away, not end the process — the analyst would
        // otherwise lose their protection indicator by reflex.
        e.Cancel = true;
        Hide();
        base.OnClosing(e);
    }

    private void OnViewModelChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(TrayViewModel.Panel))
        {
            Render(_viewModel.Panel);
        }
    }

    private void Render(TrayPanelModel panel)
    {
        _rendering = true;
        try
        {
            Headline.Text = panel.Headline;
            Headline.Foreground = BrushFor(panel.Tone);
            StateDot.Fill = BrushFor(panel.Tone);
            Detail.Text = panel.Detail;

            SetVisible(AlertBox, panel.Alert is not null);
            AlertText.Text = panel.Alert ?? string.Empty;

            LoggingLabel.Text = panel.LoggingLabel;
            LoggingLabel.Foreground = BrushFor(panel.LoggingTone);
            LoggingPill.BorderBrush = panel.LoggingTone == TrayTone.Neutral
                ? Resource("Line")
                : BrushFor(panel.LoggingTone);

            SetVisible(SensitiveLine, panel.SensitiveLine is not null);
            SensitiveLine.Text = panel.SensitiveLine ?? string.Empty;

            SetVisible(SessionRow, panel.SessionLine is not null);
            SessionLine.Text = panel.SessionLine ?? string.Empty;

            SetVisible(NoticeBox, panel.Notice is not null);
            NoticeText.Text = panel.Notice ?? string.Empty;

            RenderRegions(panel);

            SetVisible(
                LaunchButton,
                panel.Actions.HasFlag(TrayActions.LaunchResearchBrowser) && _viewModel.HasResearchBrowserLauncher);
            SetVisible(StartButton, panel.Actions.HasFlag(TrayActions.StartSession));
            SetVisible(RetryButton, panel.Actions.HasFlag(TrayActions.Reconnect));
            SetVisible(EndButton, panel.Actions.HasFlag(TrayActions.EndSession));
            SetVisible(RequestButton, panel.Actions.HasFlag(TrayActions.RequestSensitive));
            SetVisible(ActivateButton, panel.Actions.HasFlag(TrayActions.ActivateSensitive));
            SetVisible(WithdrawButton, panel.Actions.HasFlag(TrayActions.CancelSensitive));
        }
        finally
        {
            _rendering = false;
        }
    }

    private void RenderRegions(TrayPanelModel panel)
    {
        RegionBox.IsEnabled = panel.CanChooseRegion;

        // Replace the list only when it actually changed: rebuilding it under an open dropdown
        // would close it in the analyst's face on every poll.
        if (RegionBox.ItemsSource is not IReadOnlyList<RegionChoice> current || !SameRegions(current, panel.Regions))
        {
            RegionBox.ItemsSource = panel.Regions;
        }

        if (!Equals(RegionBox.SelectedValue as string, panel.SelectedRegion))
        {
            RegionBox.SelectedValue = panel.SelectedRegion;
        }
    }

    private static bool SameRegions(IReadOnlyList<RegionChoice> left, IReadOnlyList<RegionChoice> right)
    {
        if (left.Count != right.Count)
        {
            return false;
        }

        for (var i = 0; i < left.Count; i++)
        {
            if (!string.Equals(left[i].Name, right[i].Name, StringComparison.Ordinal))
            {
                return false;
            }
        }

        return true;
    }

    private async Task RegionChangedAsync(SelectionChangedEventArgs e)
    {
        ArgumentNullException.ThrowIfNull(e);

        // Re-rendering sets SelectedValue, which raises this. Only an actual choice by the analyst
        // should reach the agent.
        if (_rendering || RegionBox.SelectedValue is not string region)
        {
            return;
        }

        if (string.Equals(region, _viewModel.Panel.SelectedRegion, StringComparison.Ordinal))
        {
            return;
        }

        await RunAsync(ct => _viewModel.SelectRegionAsync(region, ct));
    }

    private async Task RequestSensitiveAsync()
    {
        var request = _askForSensitiveRequest();
        if (request is null)
        {
            return;
        }

        await RunAsync(ct => _viewModel.RequestSensitiveAsync(request.Reference, request.Minutes, ct));
    }

    private async Task RunAsync(Func<CancellationToken, Task> operation)
    {
        IsEnabled = false;
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await operation(timeout.Token);
        }
        finally
        {
            IsEnabled = true;
        }
    }

    private static void SetVisible(UIElement element, bool visible) =>
        element.Visibility = visible ? Visibility.Visible : Visibility.Collapsed;

    private static Brush Resource(string key) => (Brush)Application.Current.Resources[key];

    private static Brush BrushFor(TrayTone tone) => tone switch
    {
        TrayTone.Good => Resource("Ok"),
        TrayTone.Warning => Resource("Warn"),
        TrayTone.Bad => Resource("Bad"),
        _ => Resource("Muted"),
    };
}

/// <summary>What the analyst typed into the sensitive-session dialog.</summary>
public sealed record SensitiveRequest(string Reference, int Minutes);
