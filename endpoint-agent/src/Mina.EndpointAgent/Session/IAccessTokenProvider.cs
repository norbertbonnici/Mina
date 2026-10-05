namespace Mina.EndpointAgent.Session;

/// <summary>
/// Supplies an Entra access token for the control-plane API. Every session issuance *and every
/// renewal* asks for a fresh token, so revocation and Conditional Access re-evaluation (device
/// compliance, risk) propagate within a lease period instead of being pinned at first sign-in.
///
/// The production provider must also answer a claims challenge: when the control plane requires a
/// Conditional Access authentication context it replies 401 with
/// <c>WWW-Authenticate: Bearer error="insufficient_claims", claims=…</c>, and the token has to be
/// re-acquired passing those claims (MSAL <c>.WithClaims(...)</c>). The configured-token stand-in
/// below cannot do that; see <see cref="TrayFedAccessTokenProvider"/> and its
/// <see cref="IClaimsChallengeReceiver"/> for the production path, which can.
/// </summary>
public interface IAccessTokenProvider
{
    Task<string> GetAccessTokenAsync(CancellationToken cancellationToken);
}

/// <summary>
/// Reads a pre-supplied token from configuration.
/// **Development and test only** — it performs no sign-in and cannot pick up revocation, and does
/// not implement <see cref="IClaimsChallengeReceiver"/> since there is nothing for it to
/// re-acquire. The production provider is <see cref="TrayFedAccessTokenProvider"/>: the tray runs
/// MSAL.NET with the WAM broker (reusing the user's existing Windows/Entra session silently,
/// FR-002, and carrying device claims for Conditional Access) and relays the token over the named
/// pipe, since the agent itself runs as SYSTEM in session 0 and cannot reach the interactive user's
/// WAM/PRT directly.
/// </summary>
public sealed class ConfiguredAccessTokenProvider(string token) : IAccessTokenProvider
{
    private readonly string _token = token ?? throw new ArgumentNullException(nameof(token));

    public Task<string> GetAccessTokenAsync(CancellationToken cancellationToken) => Task.FromResult(_token);
}
