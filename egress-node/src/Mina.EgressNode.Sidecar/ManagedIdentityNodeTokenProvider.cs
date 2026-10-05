using Azure.Core;

namespace Mina.EgressNode.Sidecar;

/// <summary>
/// The node's real identity (M4-29 item 2): an Entra token from its own managed identity
/// (system-assigned on the VMSS, ARCHITECTURE §4 — no client secret anywhere in the product).
/// </summary>
/// <remarks>
/// <see cref="ControlPlaneNodeClient"/> calls <see cref="GetTokenAsync"/> on every outbound
/// request with no caching of its own — this class owns the cache, not the credential
/// underneath it, because a bare <see cref="TokenCredential"/> makes no promise about how often
/// it is safe to call. Refreshing ahead of expiry rather than on it means a slow or failed
/// refresh attempt still leaves a real margin before the cached token actually stops working.
/// </remarks>
public sealed class ManagedIdentityNodeTokenProvider : INodeTokenProvider, IDisposable
{
    // Entra app-only tokens for a custom API are typically valid ~60-90 minutes (BACKLOG M4-29's
    // own framing of the old fixed-token dev stand-in). Five minutes of headroom is wide relative
    // to that, and matches this sidecar's own AllowlistRefreshInterval/ShipInterval cadence —
    // several refresh attempts fit inside the margin before the cached token is actually invalid.
    private static readonly TimeSpan RefreshBeforeExpiry = TimeSpan.FromMinutes(5);

    private readonly TokenCredential _credential;
    private readonly string _scope;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<ManagedIdentityNodeTokenProvider> _logger;
    private readonly SemaphoreSlim _refreshLock = new(1, 1);

    // Reference assignment is atomic in .NET; a record wrapper (rather than a nullable
    // AccessToken struct field) is what makes the lock-free fast-path read below safe from a
    // torn read while a refresh is writing a new value.
    private CachedToken? _cached;

    public ManagedIdentityNodeTokenProvider(
        TokenCredential credential,
        string scope,
        TimeProvider timeProvider,
        ILogger<ManagedIdentityNodeTokenProvider> logger)
    {
        ArgumentNullException.ThrowIfNull(credential);
        ArgumentException.ThrowIfNullOrWhiteSpace(scope);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(logger);

        _credential = credential;
        _scope = scope;
        _timeProvider = timeProvider;
        _logger = logger;
    }

    public async Task<string> GetTokenAsync(CancellationToken cancellationToken)
    {
        var now = _timeProvider.GetUtcNow();
        if (_cached is { } fresh && !NeedsRefresh(fresh, now))
        {
            return fresh.Token;
        }

        await _refreshLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Another caller (AllowlistRefreshService and AccessLogShipperService both hold a
            // reference to the same singleton) may have refreshed while this one waited.
            now = _timeProvider.GetUtcNow();
            if (_cached is { } recheck && !NeedsRefresh(recheck, now))
            {
                return recheck.Token;
            }

            AccessToken token;
            try
            {
                token = await _credential
                    .GetTokenAsync(new TokenRequestContext([_scope]), cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // Not swallowed: AllowlistRefreshService/AccessLogShipperService already retry on
                // their own polling cadence, so surfacing this to the caller rather than hiding it
                // behind a stale cached token is what keeps the node's own logs the place a
                // misconfigured or unassigned managed identity actually gets noticed.
                TokenAcquisitionLog.ManagedIdentityTokenFailed(_logger, ex);
                throw;
            }

            var acquired = new CachedToken(token.Token, token.ExpiresOn);
            _cached = acquired;
            return acquired.Token;
        }
        finally
        {
            _refreshLock.Release();
        }
    }

    public void Dispose() => _refreshLock.Dispose();

    private static bool NeedsRefresh(CachedToken cached, DateTimeOffset now) =>
        now >= cached.ExpiresOn - RefreshBeforeExpiry;

    private sealed record CachedToken(string Token, DateTimeOffset ExpiresOn);
}

/// <summary>Diagnostics for managed-identity token acquisition.</summary>
internal static partial class TokenAcquisitionLog
{
    [LoggerMessage(Level = LogLevel.Warning,
        Message = "Failed to acquire a managed-identity token for the control plane.")]
    public static partial void ManagedIdentityTokenFailed(ILogger logger, Exception exception);
}
