using Mina.EndpointAgent.Ipc;

namespace Mina.EndpointAgent.Tray;

/// <summary>
/// Keeps the agent supplied with a live Entra access token (M2-4). This is the tray's half of the
/// session-0 workaround recorded in ARCHITECTURE §3.1: the agent runs as SYSTEM and cannot reach
/// the interactive user's WAM/PRT itself, so this pushes what it acquires over the pipe rather than
/// the agent ever pulling.
/// </summary>
/// <remarks>
/// Driven by the caller on the existing status-poll cadence (<c>App.xaml.cs</c>'s timer) rather
/// than owning a timer of its own — <see cref="EnsureFreshTokenAsync"/> is cheap to call when
/// nothing needs doing, since it only acquires and submits when the held token is stale or a new
/// claims challenge has arrived.
/// </remarks>
public sealed class TokenRelayService(IEntraTokenAcquirer acquirer, TrayIpcClient client, TimeProvider clock)
{
    // Refreshed this far ahead of the token's own expiry, independent of the margin
    // TrayFedAccessTokenProvider applies on the agent side — that one protects a single in-flight
    // request; this one is how far ahead of expiry the relay itself tries to stay, so the agent is
    // very unlikely to ever see the "no token yet" state in ordinary operation.
    private static readonly TimeSpan RefreshMargin = TimeSpan.FromMinutes(10);

    private string? _lastAppliedClaims;
    private DateTimeOffset _tokenExpiresOn = DateTimeOffset.MinValue;

    /// <summary>The reason the most recent attempt did not result in a fresh token, if any.</summary>
    public string? LastFailureReason { get; private set; }

    /// <summary>
    /// Called on the tray's existing poll cadence, passing whatever
    /// <see cref="AgentStatusDto.RequiredClaims"/> the last status read carried. Acquires and
    /// submits a token only when the one already submitted is stale or a new challenge has arrived
    /// since the last successful submission — an unchanged, still-fresh token means this is a
    /// no-op. Returns true when a token was actually submitted.
    /// </summary>
    public async Task<bool> EnsureFreshTokenAsync(string? requiredClaims, CancellationToken cancellationToken)
    {
        var now = clock.GetUtcNow();
        var challengeIsNew = !string.IsNullOrEmpty(requiredClaims)
            && !string.Equals(requiredClaims, _lastAppliedClaims, StringComparison.Ordinal);

        // No token submitted yet reads as "stale" via the MinValue default -- computed as a flag
        // rather than by subtracting RefreshMargin from _tokenExpiresOn directly, since MinValue
        // minus a positive margin underflows DateTimeOffset's representable range.
        var stale = _tokenExpiresOn == DateTimeOffset.MinValue || now >= _tokenExpiresOn - RefreshMargin;
        if (!challengeIsNew && !stale)
        {
            return false;
        }

        var result = await acquirer.AcquireAsync(requiredClaims, cancellationToken).ConfigureAwait(false);
        if (!result.Succeeded || result.AccessToken is not { } token || result.ExpiresOn is not { } expiresOn)
        {
            LastFailureReason = result.FailureReason ?? "The Mina sign-in did not return a usable token.";
            return false;
        }

        try
        {
            var response = await client.SubmitAccessTokenAsync(token, expiresOn, cancellationToken)
                .ConfigureAwait(false);
            if (!response.Ok)
            {
                // The agent validated the token/expiry and refused it. Treat like an acquisition
                // failure -- retried next call -- rather than silently pretending it landed.
                LastFailureReason = response.Error ?? "The agent refused the access token.";
                return false;
            }
        }
        catch (Exception ex) when (ex is AgentUnavailableException or TrayProtocolException or IOException
                                    or ObjectDisposedException)
        {
            // The agent will keep asking on its own retry loop; this attempt was just wasted, not
            // a reason to stop trying on the next call.
            LastFailureReason = ex.Message;
            return false;
        }

        _tokenExpiresOn = expiresOn;
        _lastAppliedClaims = requiredClaims;
        LastFailureReason = null;
        return true;
    }
}
