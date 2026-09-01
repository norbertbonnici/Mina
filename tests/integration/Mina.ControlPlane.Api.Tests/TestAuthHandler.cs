using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Mina.ControlPlane.Api.Tests;

/// <summary>
/// Test authentication scheme standing in for Entra. It reads identity from request headers so
/// each test can present a chosen principal without a real token:
///   X-Test-Oid, X-Test-Upn, X-Test-Roles (comma-separated), X-Test-Device, X-Test-Acrs.
/// The role claim type is "roles" to match how Microsoft.Identity.Web surfaces app roles, so the
/// production authorization policy is exercised unchanged.
/// </summary>
public sealed class TestAuthHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string SchemeName = "Test";

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue("X-Test-Oid", out var oid) || string.IsNullOrWhiteSpace(oid))
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        var claims = new List<Claim>
        {
            new("oid", oid.ToString()),
            new("preferred_username", Request.Headers["X-Test-Upn"].FirstOrDefault() ?? "analyst@fiaumalta.org"),
        };

        var device = Request.Headers["X-Test-Device"].FirstOrDefault();
        if (!string.IsNullOrEmpty(device))
        {
            claims.Add(new Claim("deviceid", device));
        }

        // Conditional Access authentication contexts, as Entra emits them when a policy bound to
        // that context was satisfied for the token.
        var acrs = Request.Headers["X-Test-Acrs"].FirstOrDefault();
        if (!string.IsNullOrEmpty(acrs))
        {
            claims.AddRange(acrs.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(value => new Claim("acrs", value)));
        }

        var roles = Request.Headers["X-Test-Roles"].FirstOrDefault();
        if (!string.IsNullOrEmpty(roles))
        {
            claims.AddRange(roles.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(role => new Claim("roles", role)));
        }

        var identity = new ClaimsIdentity(claims, SchemeName, "preferred_username", "roles");
        var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName);
        return Task.FromResult(AuthenticateResult.Success(ticket));
    }
}
