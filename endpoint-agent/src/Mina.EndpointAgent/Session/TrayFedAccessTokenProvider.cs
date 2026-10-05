namespace Mina.EndpointAgent.Session;

/// <summary>
/// Raised when no usable Entra access token is currently held. Distinguished from other failures
/// so <see cref="ResearchSessionManager"/> and <c>ProtectedPathWorker</c> treat "the tray has not
/// supplied one yet" as the same kind of transient, retry-on-backoff condition as an unreachable
/// control plane, rather than a fault that should surface differently.
/// </summary>
public sealed class NoAccessTokenAvailableException(string message) : Exception(message);

/// <summary>
/// Implemented by an <see cref="IAccessTokenProvider"/> that can act on a Conditional Access
/// claims challenge, so <see cref="ControlPlaneClient"/> can hand one off without needing to know
/// how — or whether — the concrete provider does anything with it. The development
/// <see cref="ConfiguredAccessTokenProvider"/> does not implement this, since there is nothing to
/// re-acquire.
/// </summary>
public interface IClaimsChallengeReceiver
{
    /// <summary>
    /// <paramref name="claimsChallenge"/> is the raw, base64-decoded claims JSON from the control
    /// plane's <c>WWW-Authenticate: Bearer error="insufficient_claims", claims="..."</c> header —
    /// exactly what MSAL's <c>.WithClaims(...)</c> expects, so nothing downstream needs to know the
    /// wire format.
    /// </summary>
    void RecordClaimsChallenge(string claimsChallenge);
}

/// <summary>
/// Production access-token source for M2-4 (Windows). WAM broker sign-in has to run in the
/// interactive user's own logon session — the agent runs as SYSTEM in session 0 and has no access
/// to that user's PRT (ARCHITECTURE §3.1's session-0 problem applies here too, not only to
/// research-browser launch) — so the tray performs the acquisition and hands the result across the
/// existing ACL'd named pipe (<see cref="Ipc.TrayOperations.SubmitAccessToken"/>), and this class
/// just holds whatever the tray most recently supplied.
///
/// Relaying the token this way does not hand the tray anything it could not already obtain on its
/// own: it is the analyst's own identity, reachable via the same WAM account from any code already
/// running as that user. That is a different case from the material this pipe deliberately never
/// exposes — the session's client-certificate private key and CSR material (see
/// <see cref="Ipc.AgentStatusDto"/>'s own remarks) — which stay in the SYSTEM process throughout.
/// </summary>
public sealed class TrayFedAccessTokenProvider(TimeProvider clock) : IAccessTokenProvider, IClaimsChallengeReceiver
{
    // Stop using a token this far before it actually expires, so a request in flight cannot race
    // the tray's own refresh cycle and hand the control plane a token that expires mid-request.
    private static readonly TimeSpan ExpiryMargin = TimeSpan.FromMinutes(2);

    private readonly Lock _gate = new();
    private string? _token;
    private DateTimeOffset _expiresOn;
    private string? _requiredClaims;

    public Task<string> GetAccessTokenAsync(CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            if (_token is not null && clock.GetUtcNow() < _expiresOn - ExpiryMargin)
            {
                return Task.FromResult(_token);
            }
        }

        throw new NoAccessTokenAvailableException(
            "No current Entra access token from the tray yet. Waiting for the tray to sign in or refresh.");
    }

    /// <summary>Records a token the tray just acquired. Called from the pipe; validated there.</summary>
    public void Submit(string token, DateTimeOffset expiresOn)
    {
        lock (_gate)
        {
            _token = token;
            _expiresOn = expiresOn;

            // A fresh token might be exactly the re-acquisition the pending challenge asked for.
            // The next control-plane call is what actually proves that; clear it optimistically and
            // let RecordClaimsChallenge re-set it if the same challenge comes back.
            _requiredClaims = null;
        }
    }

    /// <inheritdoc />
    public void RecordClaimsChallenge(string claimsChallenge)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(claimsChallenge);
        lock (_gate)
        {
            _requiredClaims = claimsChallenge;
        }
    }

    /// <summary>The outstanding claims challenge, if any, for the tray status to report.</summary>
    public string? RequiredClaims
    {
        get { lock (_gate) { return _requiredClaims; } }
    }
}
