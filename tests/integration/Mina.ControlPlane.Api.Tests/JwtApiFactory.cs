using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Mina.ControlPlane.Api.Tests;

/// <summary>
/// Hosts the real control-plane API with the real "Bearer" JWT scheme still doing real signature,
/// issuer, audience and lifetime validation — unlike <see cref="MinaApiFactory"/>, which replaces
/// authentication with a header-driven test scheme so every other test file can focus on
/// authorization without a live Entra tenant. That trade means nothing in this repository, before
/// this file, exercised <c>Microsoft.Identity.Web</c>'s actual token-validation pipeline (confirmed
/// by grep: every integration test authenticates via <c>X-Test-*</c> headers). A wrong-audience
/// token reached production once, live, undetected until deployment (M4-29's `AzureAd:Audience`
/// fix) — this factory exists so that class of bug is a test, not a live incident.
/// </summary>
/// <remarks>
/// Overrides <see cref="JwtBearerOptions"/> in place via <c>PostConfigure</c> rather than adding a
/// second scheme: ASP.NET Core throws if the same scheme name ("Bearer") is registered twice, and
/// this deliberately keeps testing the *same* scheme <c>Program.cs</c> registers, not a stand-in.
/// Replacing <see cref="JwtBearerOptions.TokenValidationParameters"/> wholesale (not mutating it)
/// deliberately drops Identity.Web's own multi-tenant issuer validator along with it, in favour of
/// the framework's standard, unmodified issuer/audience/lifetime/signature checks — those are
/// exactly the mechanism under test, and Entra's own tenant-resolution logic is Microsoft's to
/// test, not this platform's.
/// </remarks>
/// <remarks>
/// Sets <see cref="JwtBearerOptions.ConfigurationManager"/> directly to a
/// <see cref="StaticConfigurationManager{T}"/>, not <see cref="JwtBearerOptions.Configuration"/> --
/// an earlier version of this factory set <c>Configuration</c> instead, on the theory that it would
/// be consumed the same way. It is not: <c>Microsoft.Identity.Web</c>'s own <c>PostConfigure</c>
/// (registered inside <c>AddMicrosoftIdentityWebApi</c>, in <c>Program.cs</c>, before this factory's
/// runs) already builds a live <c>ConfigurationManager</c> from <c>Authority</c> the moment it runs,
/// because <c>Configuration</c> is still null at that point -- setting <c>Configuration</c>
/// afterwards has nothing left to feed. Confirmed live, not assumed: the first version's tests
/// logged real outbound TLS attempts to <c>login.microsoftonline.com</c> for this fake tenant
/// (IdentityModel <c>IDX20807</c>) on every run, up to a 60 s backchannel timeout each if the
/// network failed shut rather than refusing -- exactly the non-hermetic behaviour this factory's
/// own doc comment claimed did not happen. Assigning <c>ConfigurationManager</c> directly
/// overwrites Identity.Web's instance outright, which is why this property (not <c>Configuration</c>)
/// is the one to set.
/// </remarks>
public sealed class JwtApiFactory : WebApplicationFactory<Program>
{
    public const string TestIssuer = "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0";
    public const string TestAudience = "22222222-2222-2222-2222-222222222222";

    public static readonly RSA SigningKeyMaterial = RSA.Create(2048);
    public static readonly RsaSecurityKey SigningKey = new(SigningKeyMaterial) { KeyId = "test-signing-key" };

    public static readonly RSA OtherKeyMaterial = RSA.Create(2048);
    public static readonly RsaSecurityKey OtherKey = new(OtherKeyMaterial) { KeyId = "wrong-signing-key" };

    private static readonly Dictionary<string, string?> Config = new()
    {
        ["AzureAd:Instance"] = "https://login.microsoftonline.com/",
        ["AzureAd:TenantId"] = "11111111-1111-1111-1111-111111111111",
        ["AzureAd:ClientId"] = TestAudience,
        ["Mina:Session:AnalystRole"] = "Mina.Analyst",
        ["Mina:Session:LeaseTtl"] = "01:00:00",
        ["Mina:Regions:Approved:0"] = "westeurope",
        ["Mina:Regions:Active:0"] = "westeurope",
        ["Mina:Egress:Regions:westeurope:Host"] = "20.0.0.1",
        ["Mina:Egress:Regions:westeurope:Port"] = "443",
        ["Mina:Egress:Regions:westeurope:ServerName"] = "westeurope.egress.mina",
    };

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((_, cfg) => cfg.AddInMemoryCollection(Config));

        builder.ConfigureTestServices(services =>
        {
            services.PostConfigure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, options =>
            {
                // A static ConfigurationManager -- not the `Configuration` property, see the type's
                // own remarks above -- means no metadata fetch of any kind, real or otherwise. A
                // signing key baked in locally, via TokenValidationParameters below, is the whole
                // point; this is what actually makes that true rather than merely intended.
                options.RequireHttpsMetadata = false;
                options.ConfigurationManager =
                    new Microsoft.IdentityModel.Protocols.StaticConfigurationManager<
                        Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectConfiguration>(
                        new Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectConfiguration());
                options.MapInboundClaims = false;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = TestIssuer,
                    ValidateAudience = true,
                    ValidAudience = TestAudience,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = SigningKey,
                    ClockSkew = TimeSpan.FromSeconds(30),
                    RoleClaimType = "roles",
                    NameClaimType = "preferred_username",
                };
            });
        });
    }

    /// <summary>
    /// Builds a real, signed JWT. Every parameter defaults to a value the API should accept, so a
    /// test only overrides the one thing it means to break.
    /// </summary>
    public static string IssueToken(
        string oid = "oid-jwt-1",
        string upn = "jwt-analyst@example.org",
        string[]? roles = null,
        string? deviceId = "device-jwt-1",
        string issuer = TestIssuer,
        string audience = TestAudience,
        RsaSecurityKey? signingKey = null,
        DateTime? notBefore = null,
        DateTime? expires = null,
        string? algorithm = null)
    {
        var now = DateTime.UtcNow;
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            NotBefore = notBefore ?? now.AddMinutes(-5),
            Expires = expires ?? now.AddHours(1),
            IssuedAt = now,
            Claims = new Dictionary<string, object>
            {
                ["oid"] = oid,
                ["preferred_username"] = upn,
            },
        };

        if (signingKey is not null)
        {
            descriptor.SigningCredentials = new SigningCredentials(signingKey, algorithm ?? SecurityAlgorithms.RsaSha256);
        }

        if (deviceId is not null)
        {
            descriptor.Claims["deviceid"] = deviceId;
        }

        if (roles is { Length: > 0 })
        {
            descriptor.Claims["roles"] = roles;
        }

        return new JsonWebTokenHandler().CreateToken(descriptor); // unsigned (alg:none) when SigningCredentials was never set
    }
}
