using System.ComponentModel;
using System.Runtime.CompilerServices;
using Mina.EndpointAgent.Ipc;

namespace Mina.EndpointAgent.Tray;

/// <summary>
/// Drives the panel: polls the agent, runs the analyst's commands, and re-projects
/// <see cref="Panel"/> after each. The shell binds to <see cref="Panel"/> and nothing else.
/// </summary>
/// <remarks>
/// <para>
/// Deliberately unlike a typical view model, this one holds no state the agent could contradict.
/// Every command discards what it thought it knew and adopts the status the agent returned, so the
/// panel cannot drift into claiming a protection the endpoint does not have.
/// </para>
/// <para>
/// Awaits here intentionally do not use <c>ConfigureAwait(false)</c>, unlike the rest of the
/// codebase: the continuations raise <see cref="PropertyChanged"/>, which WPF requires on the UI
/// thread.
/// </para>
/// </remarks>
public sealed class TrayViewModel : INotifyPropertyChanged, IAsyncDisposable
{
    private readonly TrayIpcClient _client;
    private readonly TimeProvider _clock;
    private readonly ResearchBrowserLauncher? _researchBrowserLauncher;

    private AgentStatusDto? _status;
    private string? _notice;
    private TrayPanelModel _panel;

    public TrayViewModel(TrayIpcClient client, TimeProvider clock, ResearchBrowserLauncher? researchBrowserLauncher = null)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _clock = clock ?? throw new ArgumentNullException(nameof(clock));
        _researchBrowserLauncher = researchBrowserLauncher;
        _panel = TrayPanel.Unavailable("Contacting the Mina agent…");
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    /// <summary>What the panel should currently show.</summary>
    public TrayPanelModel Panel
    {
        get => _panel;
        private set
        {
            if (_panel == value)
            {
                return;
            }

            _panel = value;
            OnPropertyChanged();
        }
    }

    /// <summary>Reads the agent's status. Safe to call on a timer.</summary>
    public Task RefreshAsync(CancellationToken cancellationToken) =>
        RunAsync(ct => _client.GetStatusAsync(ct), clearNotice: true, cancellationToken);

    public Task ReconnectAsync(CancellationToken cancellationToken) =>
        RunAsync(ct => _client.ReconnectAsync(ct), clearNotice: true, cancellationToken);

    /// <summary>Starts a session again after the analyst ended one. The agent treats it as a reconnect.</summary>
    public Task StartSessionAsync(CancellationToken cancellationToken) => ReconnectAsync(cancellationToken);

    public Task EndSessionAsync(CancellationToken cancellationToken) =>
        RunAsync(ct => _client.EndSessionAsync(ct), clearNotice: true, cancellationToken);

    public Task SelectRegionAsync(string region, CancellationToken cancellationToken) =>
        RunAsync(ct => _client.SelectRegionAsync(region, ct), clearNotice: true, cancellationToken);

    public Task RequestSensitiveAsync(
        string justificationReference, int minutes, CancellationToken cancellationToken) =>
        RunAsync(
            ct => _client.RequestSensitiveAsync(justificationReference, minutes, ct),
            clearNotice: true,
            cancellationToken);

    public Task ActivateSensitiveAsync(CancellationToken cancellationToken) =>
        RunAsync(ct => _client.ActivateSensitiveAsync(ct), clearNotice: true, cancellationToken);

    public Task CancelSensitiveAsync(CancellationToken cancellationToken) =>
        RunAsync(ct => _client.CancelSensitiveAsync(ct), clearNotice: true, cancellationToken);

    /// <summary>
    /// Re-projects the panel from the status already held, so countdowns move between polls without
    /// asking the agent — and therefore without asking the control plane — once a second.
    /// </summary>
    public void Tick() => Project();

    /// <summary>True when the last exchange with the agent succeeded.</summary>
    public bool IsConnected => _status is not null;

    /// <summary>
    /// The claims challenge the agent's last status reported, if any (M2-4) — what
    /// <see cref="TokenRelayService"/> must pass to the next acquisition's <c>.WithClaims(...)</c>.
    /// </summary>
    public string? RequiredClaims => _status?.RequiredClaims;

    /// <summary>
    /// Whether this deployment is configured to launch the research browser at all — separate from
    /// <see cref="TrayActions.LaunchResearchBrowser"/>, which says only that the protected path is
    /// currently up. The shell combines both before showing the button.
    /// </summary>
    public bool HasResearchBrowserLauncher => _researchBrowserLauncher is not null;

    /// <summary>
    /// Launches the research browser pinned to the agent's current proxy port. A no-op — not an
    /// error — when no launcher is configured or the protected path is not actually up, since
    /// those are exactly the conditions the shell already hides the button for; this only guards
    /// against a stale click racing a status change.
    /// </summary>
    public void LaunchResearchBrowser()
    {
        if (_researchBrowserLauncher is null
            || _status is not { State: ProtectedPathStates.Protected, ProxyPort: > 0 } status)
        {
            return;
        }

        try
        {
            _researchBrowserLauncher.Launch(status.ProxyPort);
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            _notice = "The research browser could not be started: " + ex.Message;
            Project();
        }
    }

    /// <summary>
    /// The ceiling the agent will accept for a suppression window, for the request dialog. Falls
    /// back only until the first status arrives.
    /// </summary>
    public int MaxSensitiveMinutes => _status is { MaxSensitiveMinutes: > 0 } status ? status.MaxSensitiveMinutes : 240;

    private async Task RunAsync(
        Func<CancellationToken, Task<TrayResponse>> operation, bool clearNotice, CancellationToken cancellationToken)
    {
        if (clearNotice)
        {
            _notice = null;
        }

        try
        {
            var response = await operation(cancellationToken);

            // A refusal still carries a status, and it is the freshest one available — adopt it, so
            // "that region is not available to you" appears over a panel that is otherwise correct.
            if (response.Status is not null)
            {
                _status = response.Status;
            }

            if (!response.Ok)
            {
                _notice = response.Error ?? "The agent refused that action.";
            }
        }
        catch (AgentUnavailableException ex)
        {
            _status = null;
            _notice = ex.Message;
        }
        catch (TrayProtocolException)
        {
            _status = null;
            _notice = "The Mina agent answered in a way this version of the tray does not understand.";
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException)
        {
            _status = null;
            _notice = "The connection to the Mina agent dropped.";
        }

        Project();
    }

    private void Project()
    {
        var now = _clock.GetUtcNow();
        Panel = _status is null
            ? TrayPanel.Unavailable(_notice ?? "The Mina agent service is not responding.")
            : TrayPanel.From(_status, now, _notice);
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));

    public ValueTask DisposeAsync() => _client.DisposeAsync();
}
