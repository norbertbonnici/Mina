using Microsoft.Extensions.Options;
using Mina.EndpointAgent.Configuration;

namespace Mina.EndpointAgent.Ipc;

/// <summary>
/// The agent's view of its own protected path, shared between the worker that maintains it and the
/// tray service that reports it. The worker is the only writer of path state; the tray service
/// writes only what an analyst is permitted to choose, and always through a validated method.
/// </summary>
/// <remarks>
/// This is also where "the analyst ended their session" is remembered. Without it, ending a session
/// would last exactly one tick before the worker helpfully rebuilt it.
/// </remarks>
public sealed class AgentRuntimeState : IDisposable
{
    private readonly Lock _gate = new();
    private readonly SemaphoreSlim _wake = new(0, 1);

    private string _region;
    private bool _suspended;
    private string _pathState = ProtectedPathStates.Connecting;
    private string? _reason;
    private int _consecutiveFailures;
    private DateTimeOffset? _nextAttemptAt;
    private int _proxyPort;
    private IReadOnlyList<string> _selectableRegions = [];
    private SensitiveRequestDto? _sensitive;

    public AgentRuntimeState(IOptions<MinaAgentOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _region = options.Value.Region;
    }

    /// <summary>Region the next session will be established in.</summary>
    public string Region
    {
        get { lock (_gate) { return _region; } }
    }

    /// <summary>True once the analyst has ended their session, until they start another.</summary>
    public bool Suspended
    {
        get { lock (_gate) { return _suspended; } }
    }

    public string PathState
    {
        get { lock (_gate) { return _pathState; } }
    }

    public IReadOnlyList<string> SelectableRegions
    {
        get { lock (_gate) { return _selectableRegions; } }
    }

    public SensitiveRequestDto? SensitiveRequest
    {
        get { lock (_gate) { return _sensitive; } }
    }

    /// <summary>The path is up and the research browser is pinned to <paramref name="proxyPort"/>.</summary>
    public void ReportProtected(int proxyPort)
    {
        lock (_gate)
        {
            _pathState = ProtectedPathStates.Protected;
            _reason = null;
            _consecutiveFailures = 0;
            _nextAttemptAt = null;
            _proxyPort = proxyPort;
        }
    }

    /// <summary>An attempt is under way. Browsing does not work yet, and the tray should say so.</summary>
    public void ReportConnecting()
    {
        lock (_gate)
        {
            _pathState = ProtectedPathStates.Connecting;
            _proxyPort = 0;
        }
    }

    /// <summary>
    /// The path is down and could not be rebuilt. <paramref name="reason"/> is a platform fact —
    /// a refusal code or a transport failure — and never anything the analyst was browsing.
    /// </summary>
    public void ReportFailed(string reason, DateTimeOffset? nextAttemptAt)
    {
        lock (_gate)
        {
            _pathState = ProtectedPathStates.Failed;
            _reason = reason;
            _consecutiveFailures++;
            _nextAttemptAt = nextAttemptAt;
            _proxyPort = 0;
        }
    }

    /// <summary>The analyst ended the session; stop rebuilding it.</summary>
    public void Suspend()
    {
        lock (_gate)
        {
            _suspended = true;
            _pathState = ProtectedPathStates.Stopped;
            _reason = null;
            _consecutiveFailures = 0;
            _nextAttemptAt = null;
            _proxyPort = 0;
            _sensitive = null;
        }
    }

    /// <summary>The analyst asked for a session again.</summary>
    public void Resume()
    {
        lock (_gate)
        {
            _suspended = false;
            _pathState = ProtectedPathStates.Connecting;
            _reason = null;
            _consecutiveFailures = 0;
            _nextAttemptAt = null;
        }
    }

    /// <summary>
    /// Records the region the analyst chose. Callers must have checked it against
    /// <see cref="SelectableRegions"/> first — this method stores a decision, it does not make one.
    /// </summary>
    public void SetRegion(string region)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(region);
        lock (_gate)
        {
            _region = region;
        }
    }

    /// <summary>Caches the regions the control plane offers this analyst.</summary>
    public void SetSelectableRegions(IReadOnlyList<string> regions)
    {
        ArgumentNullException.ThrowIfNull(regions);
        lock (_gate)
        {
            _selectableRegions = [.. regions];
        }
    }

    /// <summary>Tracks the suppression request in flight, or clears it when there is none.</summary>
    public void SetSensitiveRequest(SensitiveRequestDto? request)
    {
        lock (_gate)
        {
            _sensitive = request;
        }
    }

    /// <summary>An immutable reading of everything except the session itself.</summary>
    public RuntimeSnapshot Snapshot()
    {
        lock (_gate)
        {
            return new RuntimeSnapshot(
                _suspended ? ProtectedPathStates.Stopped : _pathState,
                _region,
                _reason,
                _consecutiveFailures,
                _nextAttemptAt,
                _proxyPort,
                _selectableRegions,
                _sensitive);
        }
    }

    /// <summary>Brings the worker's next tick forward, so a tray command takes effect at once.</summary>
    public void Wake()
    {
        lock (_gate)
        {
            if (_wake.CurrentCount == 0)
            {
                _wake.Release();
            }
        }
    }

    /// <summary>Waits for the next tick, returning early if <see cref="Wake"/> is called.</summary>
    public async Task WaitForNextTickAsync(TimeSpan interval, TimeProvider clock, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(clock);

        // SemaphoreSlim's own timeout uses the system clock, which tests cannot advance. Racing it
        // against a TimeProvider delay keeps the loop testable without a real wall-clock wait.
        using var timeout = new CancellationTokenSource();
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeout.Token);

        var delay = Task.Delay(interval, clock, linked.Token);
        var woken = _wake.WaitAsync(linked.Token);

        var finished = await Task.WhenAny(delay, woken).ConfigureAwait(false);
        await timeout.CancelAsync().ConfigureAwait(false);

        try
        {
            await finished.ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            // The loser of the race was cancelled on purpose.
        }

        cancellationToken.ThrowIfCancellationRequested();
    }

    public void Dispose() => _wake.Dispose();
}

/// <summary>An immutable reading of the agent's runtime state.</summary>
public sealed record RuntimeSnapshot(
    string PathState,
    string Region,
    string? Reason,
    int ConsecutiveFailures,
    DateTimeOffset? NextAttemptAt,
    int ProxyPort,
    IReadOnlyList<string> SelectableRegions,
    SensitiveRequestDto? Sensitive);
