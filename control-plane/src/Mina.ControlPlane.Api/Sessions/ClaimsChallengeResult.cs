using System.Text;
using System.Text.Json;

namespace Mina.ControlPlane.Api.Sessions;

/// <summary>
/// A Conditional Access claims challenge: 401 with a <c>WWW-Authenticate</c> header naming the
/// authentication context the token must satisfy.
/// </summary>
/// <remarks>
/// This is what makes requiring an auth context workable rather than a wall. The client re-acquires
/// its token asking for the named context; Entra satisfies it silently from the primary refresh
/// token when the device meets the policy bound to that context, and does not when it does not. A
/// flat 403 would give a compliant device no way to proceed and would be indistinguishable from a
/// genuine refusal — so the platform could not tell "the client did not ask for the context" from
/// "the device is not compliant".
///
/// The body stays empty on purpose: the challenge is the header, and the response should not
/// describe tenant policy to an unauthenticated-for-this-purpose caller.
/// </remarks>
internal sealed class ClaimsChallengeResult(string authContextId) : IResult
{
    public Task ExecuteAsync(HttpContext httpContext)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        var claims = JsonSerializer.Serialize(new
        {
            access_token = new { acrs = new { essential = true, value = authContextId } },
        });

        // Base64 per the claims-challenge convention, quoted because the value contains characters
        // that are not valid in a bare auth-param token.
        var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(claims));

        httpContext.Response.StatusCode = StatusCodes.Status401Unauthorized;
        httpContext.Response.Headers.WWWAuthenticate =
            $"Bearer error=\"insufficient_claims\", claims=\"{encoded}\"";
        return Task.CompletedTask;
    }
}
