using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace Mina.ManagementUi.Infrastructure;

/// <summary>
/// Signs every request in as a configured identity, so the screens can be reviewed without an Entra
/// tenant.
/// </summary>
/// <remarks>
/// **This is an authentication bypass.** It is refused unless the host is in the Development
/// environment *and* <c>Mina:Ui:DevSignIn:Enabled</c> is explicitly true — see
/// <c>ManagementUiAuthentication</c>, which throws at startup rather than silently allowing it
/// anywhere else. It exists so the UI can be demonstrated locally; it must never be reachable in
/// test or production, where Entra OIDC is the only sign-in.
/// </remarks>
public sealed class DevSignInAuthHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    IOptions<DevSignInOptions> devOptions,
    ILoggerFactory logger,
    UrlEncoder encoder) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string SchemeName = "DevSignIn";

    private readonly DevSignInOptions _dev = devOptions.Value;

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var claims = new List<Claim>
        {
            new("oid", _dev.ObjectId),
            new("preferred_username", _dev.UserPrincipalName),
        };

        claims.AddRange(_dev.Roles.Select(role => new Claim("roles", role)));

        var identity = new ClaimsIdentity(claims, SchemeName, "preferred_username", "roles");
        return Task.FromResult(AuthenticateResult.Success(
            new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName)));
    }
}

/// <summary>Identity presented by the development sign-in.</summary>
public sealed class DevSignInOptions
{
    public const string Section = "Mina:Ui:DevSignIn";

    public bool Enabled { get; set; }

    public string ObjectId { get; set; } = "oid-dev-approver";

    public string UserPrincipalName { get; set; } = "dev.approver@example.org";

    public IList<string> Roles { get; set; } = ["Mina.Approver"];
}
