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

    private AgentStatusDto? _status;
    private string? _notice;
    private TrayPanelModel _panel;

    public TrayViewModel(TrayIpcClient client, TimeProvider clock)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _clock = clock ?? throw new ArgumentNullException(nameof(clock));
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
