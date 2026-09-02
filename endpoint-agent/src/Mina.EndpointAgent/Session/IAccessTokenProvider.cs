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
/// below cannot do that, so the auth-context requirement is not usable end to end until M2-4.
/// </summary>
public interface IAccessTokenProvider
{
    Task<string> GetAccessTokenAsync(CancellationToken cancellationToken);
}

/// <summary>
/// Reads a pre-supplied token from configuration.
/// **Development and test only** — it performs no sign-in and cannot pick up revocation.
/// The production provider is MSAL.NET with the WAM broker, which reuses the user's existing
/// Windows/Entra session silently (FR-002) and carries device claims for Conditional Access; it
/// is Windows-only and lands with the hardened service in M2-4.
/// </summary>
public sealed class ConfiguredAccessTokenProvider(string token) : IAccessTokenProvider
{
    private readonly string _token = token ?? throw new ArgumentNullException(nameof(token));

    public Task<string> GetAccessTokenAsync(CancellationToken cancellationToken) => Task.FromResult(_token);
}
