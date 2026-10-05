using System.IO.Pipes;

namespace Mina.EndpointAgent.Ipc;

/// <summary>Raised when the agent cannot be reached at all.</summary>
public sealed class AgentUnavailableException : Exception
{
    public AgentUnavailableException()
    {
    }

    public AgentUnavailableException(string message)
        : base(message)
    {
    }

    public AgentUnavailableException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// The tray's end of the pipe. Holds one connection and reconnects transparently, because the agent
/// is a service that can restart under the tray — a panel that needed restarting every time the
/// service was patched would train analysts to ignore it.
/// </summary>
/// <remarks>
/// Nothing here is trusted by the agent. Every operation is re-validated on the far side, so a
/// tampered tray can only ask for things the agent would have allowed anyway.
/// </remarks>
public sealed class TrayIpcClient(
    string pipeName = TrayProtocol.PipeName, string serverName = ".", TimeSpan? connectTimeout = null)
    : IAsyncDisposable
{
    private readonly SemaphoreSlim _mutex = new(1, 1);

    // Production callers get TrayProtocol.ConnectTimeout unchanged — this parameter exists so a
    // test can give a freshly started, not-yet-warm server (a cold pipe on a loaded CI runner) more
    // room to accept the first connection than the real UX budget allows, without weakening the
    // real one: an actual tray polling an actual agent should fail fast at the production value,
    // not wait out whatever margin a test needed.
    private readonly TimeSpan _connectTimeout = connectTimeout ?? TrayProtocol.ConnectTimeout;
    private NamedPipeClientStream? _pipe;
    private bool _disposed;

    public async Task<TrayResponse> SendAsync(TrayRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ObjectDisposedException.ThrowIf(_disposed, this);

        await _mutex.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            try
            {
                return await ExchangeAsync(request, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException or TrayProtocolException)
            {
                // A dropped pipe usually means the service restarted. Reconnect once and retry; a
                // second failure is reported rather than looped on.
                Reset();
                return await ExchangeAsync(request, cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            _mutex.Release();
        }
    }

    public Task<TrayResponse> GetStatusAsync(CancellationToken cancellationToken) =>
        SendAsync(new TrayRequest { Op = TrayOperations.Status }, cancellationToken);

    public Task<TrayResponse> SelectRegionAsync(string region, CancellationToken cancellationToken) =>
        SendAsync(new TrayRequest { Op = TrayOperations.SelectRegion, Region = region }, cancellationToken);

    public Task<TrayResponse> ReconnectAsync(CancellationToken cancellationToken) =>
        SendAsync(new TrayRequest { Op = TrayOperations.Reconnect }, cancellationToken);

    public Task<TrayResponse> EndSessionAsync(CancellationToken cancellationToken) =>
        SendAsync(new TrayRequest { Op = TrayOperations.EndSession }, cancellationToken);

    public Task<TrayResponse> RequestSensitiveAsync(
        string justificationReference, int minutes, CancellationToken cancellationToken) =>
        SendAsync(
            new TrayRequest
            {
                Op = TrayOperations.RequestSensitive,
                JustificationReference = justificationReference,
                Minutes = minutes,
            },
            cancellationToken);

    public Task<TrayResponse> ActivateSensitiveAsync(CancellationToken cancellationToken) =>
        SendAsync(new TrayRequest { Op = TrayOperations.ActivateSensitive }, cancellationToken);

    public Task<TrayResponse> CancelSensitiveAsync(CancellationToken cancellationToken) =>
        SendAsync(new TrayRequest { Op = TrayOperations.CancelSensitive }, cancellationToken);

    /// <summary>Hands the agent a token the tray just acquired via the WAM broker (M2-4).</summary>
    public Task<TrayResponse> SubmitAccessTokenAsync(
        string accessToken, DateTimeOffset expiresOn, CancellationToken cancellationToken) =>
        SendAsync(
            new TrayRequest
            {
                Op = TrayOperations.SubmitAccessToken,
                AccessToken = accessToken,
                AccessTokenExpiresOn = expiresOn,
            },
            cancellationToken);

    private async Task<TrayResponse> ExchangeAsync(TrayRequest request, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TrayProtocol.ExchangeTimeout);

        var pipe = await ConnectAsync(timeout.Token).ConfigureAwait(false);
        await TrayFraming.WriteAsync(pipe, request, TrayJsonContext.Default.TrayRequest, timeout.Token)
            .ConfigureAwait(false);

        var response = await TrayFraming
            .ReadAsync(pipe, TrayJsonContext.Default.TrayResponse, timeout.Token).ConfigureAwait(false);

        return response ?? throw new TrayProtocolException("The agent closed the pipe without answering.");
    }

    private async Task<NamedPipeClientStream> ConnectAsync(CancellationToken cancellationToken)
    {
        if (_pipe is { IsConnected: true })
        {
            return _pipe;
        }

        Reset();

        var pipe = new NamedPipeClientStream(
            serverName, pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        try
        {
            await pipe.ConnectAsync(
                    (int)_connectTimeout.TotalMilliseconds, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or TimeoutException or UnauthorizedAccessException)
        {
            await pipe.DisposeAsync().ConfigureAwait(false);
            throw new AgentUnavailableException(
                "The Mina agent service is not responding. Research browsing is unavailable until it is.", ex);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            await pipe.DisposeAsync().ConfigureAwait(false);
            throw new AgentUnavailableException("Timed out connecting to the Mina agent service.");
        }

        _pipe = pipe;
        return pipe;
    }

    private void Reset()
    {
        _pipe?.Dispose();
        _pipe = null;
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        if (_pipe is not null)
        {
            await _pipe.DisposeAsync().ConfigureAwait(false);
            _pipe = null;
        }

        _mutex.Dispose();
    }
}
