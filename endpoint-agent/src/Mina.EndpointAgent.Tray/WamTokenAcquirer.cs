using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Broker;

namespace Mina.EndpointAgent.Tray;

/// <summary>
/// Production <see cref="IEntraTokenAcquirer"/>: MSAL.NET with the WAM broker, reusing the
/// account already signed into Windows (FR-002) and — because the authority is scoped to one
/// tenant rather than <c>organizations</c> — never offering an unrelated personal Microsoft
/// account from the same Windows session. This is what has to run here rather than in the agent:
/// WAM's silent SSO is tied to the interactively logged-on user's own session, which the SYSTEM
/// agent cannot reach (ARCHITECTURE §3.1).
/// </summary>
public sealed class WamTokenAcquirer : IEntraTokenAcquirer
{
    private readonly IPublicClientApplication _app;
    private readonly string[] _scopes;

    public WamTokenAcquirer(TrayOptions options, Func<IntPtr> parentWindowHandle)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(parentWindowHandle);

        _scopes = [options.Scope];

        var brokerOptions = new BrokerOptions(BrokerOptions.OperatingSystems.Windows) { Title = "Mina" };
        _app = PublicClientApplicationBuilder.Create(options.ClientId)
            .WithAuthority(AzureCloudInstance.AzurePublic, options.TenantId)
            .WithDefaultRedirectUri()
            .WithParentActivityOrWindow(parentWindowHandle)
            .WithBroker(brokerOptions)
            .Build();
    }

    public async Task<TokenAcquisitionResult> AcquireAsync(string? claimsChallenge, CancellationToken cancellationToken)
    {
        try
        {
            AuthenticationResult result;
            if (!string.IsNullOrEmpty(claimsChallenge))
            {
                // A Conditional Access step-up is not something a cached silent token can satisfy
                // on its own -- go straight to interactive, passing the exact claims Entra named.
                result = await _app.AcquireTokenInteractive(_scopes)
                    .WithClaims(claimsChallenge)
                    .ExecuteAsync(cancellationToken)
                    .ConfigureAwait(false);
            }
            else
            {
                try
                {
                    result = await _app
                        .AcquireTokenSilent(_scopes, PublicClientApplication.OperatingSystemAccount)
                        .ExecuteAsync(cancellationToken)
                        .ConfigureAwait(false);
                }
                catch (MsalUiRequiredException)
                {
                    // No cached account, or it needs interaction the silent call cannot provide
                    // (e.g. first run). WAM's own account picker/prompt handles the rest.
                    result = await _app.AcquireTokenInteractive(_scopes)
                        .ExecuteAsync(cancellationToken)
                        .ConfigureAwait(false);
                }
            }

            return TokenAcquisitionResult.Success(result.AccessToken, result.ExpiresOn);
        }
        catch (MsalException ex)
        {
            return TokenAcquisitionResult.Failure(ex.Message);
        }
    }
}
