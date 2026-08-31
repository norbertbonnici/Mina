namespace Mina.EndpointAgent.Session;

/// <summary>
/// Supplies an Entra access token for the control-plane API. Every session issuance *and every
/// renewal* asks for a fresh token, so revocation and Conditional Access re-evaluation (device
/// compliance, risk) propagate within a lease period instead of being pinned at first sign-in.
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
