using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Mina.TestSupport;

/// <summary>
/// Stands in for Entra token validation while keeping the agent's real code path: the agent sends
/// <c>Authorization: Bearer &lt;token&gt;</c>, and here the token is a claim list
/// (<c>oid=…;upn=…;device=…;roles=…</c>) instead of a signed JWT. Nothing in the agent knows the
/// difference, so what the end-to-end tests exercise is the production request flow.
/// </summary>
public sealed class BearerTestAuthHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string SchemeName = "BearerTest";

    /// <summary>Builds a token for the given identity.</summary>
    public static string Token(string oid, string upn, string? device, string roles)
    {
        var parts = new List<string> { $"oid={oid}", $"upn={upn}", $"roles={roles}" };
        if (!string.IsNullOrEmpty(device))
        {
            parts.Add($"device={device}");
        }

        return string.Join(';', parts);
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var header = Request.Headers.Authorization.ToString();
        if (string.IsNullOrWhiteSpace(header) || !header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        var values = header["Bearer ".Length..]
            .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(pair => pair.Split('=', 2))
            .Where(pair => pair.Length == 2)
            .ToDictionary(pair => pair[0], pair => pair[1], StringComparer.OrdinalIgnoreCase);

        if (!values.TryGetValue("oid", out var oid))
        {
            return Task.FromResult(AuthenticateResult.Fail("No oid in token."));
        }

        var claims = new List<Claim>
        {
            new("oid", oid),
            new("preferred_username", values.GetValueOrDefault("upn", $"{oid}@fiaumalta.org")),
        };

        if (values.TryGetValue("device", out var device))
        {
            claims.Add(new Claim("deviceid", device));
        }

        if (values.TryGetValue("roles", out var roles))
        {
            claims.AddRange(roles.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(role => new Claim("roles", role)));
        }

        var identity = new ClaimsIdentity(claims, SchemeName, "preferred_username", "roles");
        return Task.FromResult(AuthenticateResult.Success(
            new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName)));
    }
}
