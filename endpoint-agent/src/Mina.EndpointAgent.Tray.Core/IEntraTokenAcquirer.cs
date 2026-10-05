namespace Mina.EndpointAgent.Tray;

/// <summary>Result of one Entra token acquisition attempt.</summary>
public sealed record TokenAcquisitionResult(bool Succeeded, string? AccessToken, DateTimeOffset? ExpiresOn, string? FailureReason)
{
    public static TokenAcquisitionResult Success(string accessToken, DateTimeOffset expiresOn) =>
        new(true, accessToken, expiresOn, null);

    public static TokenAcquisitionResult Failure(string reason) => new(false, null, null, reason);
}

/// <summary>
/// Acquires an Entra access token for the analyst's own identity. The production implementation
/// (<c>WamTokenAcquirer</c>, in <c>Mina.EndpointAgent.Tray</c> — Windows-only, needs a real window
/// handle and the WAM broker component) lives outside this cross-platform project so the relay
/// logic that drives it (<see cref="TokenRelayService"/>) stays under test on CI's Linux hosts,
/// same reasoning as everything else in Tray.Core.
/// </summary>
public interface IEntraTokenAcquirer
{
    /// <summary>
    /// Acquires silently first, using the account already signed into Windows, falling back to an
    /// interactive prompt only if that fails. <paramref name="claimsChallenge"/>, when not null, is
    /// the raw JSON to pass to MSAL's <c>.WithClaims(...)</c> — exactly what
    /// <c>Ipc.AgentStatusDto.RequiredClaims</c> carries — and always forces an interactive
    /// acquisition, since a Conditional Access step-up is not something a cached silent token can
    /// satisfy on its own.
    /// </summary>
    Task<TokenAcquisitionResult> AcquireAsync(string? claimsChallenge, CancellationToken cancellationToken);
}
