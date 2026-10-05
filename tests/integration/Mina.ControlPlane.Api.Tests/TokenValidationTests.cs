using System.Net;
using System.Net.Http.Headers;

namespace Mina.ControlPlane.Api.Tests;

/// <summary>
/// B5's own "Test:" column names this suite ("tampered-token suite") and it did not exist before
/// this file — every other integration test in this project authenticates through
/// <see cref="TestAuthHandler"/>'s header shortcut, so none of them ever asked
/// <c>Microsoft.Identity.Web</c>'s real JWT bearer pipeline to validate a real token. That gap is
/// not theoretical: M4-29's live deployment found a wrong-audience token rejected in production
/// with "The audience '(null)' is invalid" the first time this API's bearer validation ever saw a
/// real one, because nothing in CI could have caught it first. These tests use
/// <see cref="JwtApiFactory"/>, which keeps the real "Bearer" scheme active with a local signing
/// key in place of Entra's, so standard issuer/audience/signature/lifetime validation runs for
/// real against a token this file signs itself.
/// </summary>
public sealed class TokenValidationTests(JwtApiFactory factory) : IClassFixture<JwtApiFactory>
{
    private readonly JwtApiFactory _factory = factory;

    private HttpClient BearerClient(string token)
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client;
    }

    private Task<HttpResponseMessage> RegionsAsync(string token) =>
        BearerClient(token).GetAsync(new Uri("/api/regions", UriKind.Relative));

    [Fact]
    public async Task A_correctly_signed_token_with_the_right_claims_is_accepted()
    {
        var token = JwtApiFactory.IssueToken(roles: ["Mina.Analyst"], signingKey: JwtApiFactory.SigningKey);

        var response = await RegionsAsync(token);

        response.EnsureSuccessStatusCode(); // proves the happy path through this factory works at all
    }

    [Fact]
    public async Task Wrong_audience_is_rejected()
    {
        var token = JwtApiFactory.IssueToken(
            roles: ["Mina.Analyst"], audience: "99999999-9999-9999-9999-999999999999",
            signingKey: JwtApiFactory.SigningKey);

        var response = await RegionsAsync(token);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Wrong_issuer_is_rejected()
    {
        var token = JwtApiFactory.IssueToken(
            roles: ["Mina.Analyst"],
            issuer: "https://login.microsoftonline.com/99999999-9999-9999-9999-999999999999/v2.0",
            signingKey: JwtApiFactory.SigningKey);

        var response = await RegionsAsync(token);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task An_expired_token_is_rejected()
    {
        var token = JwtApiFactory.IssueToken(
            roles: ["Mina.Analyst"],
            notBefore: DateTime.UtcNow.AddHours(-2),
            expires: DateTime.UtcNow.AddMinutes(-10),
            signingKey: JwtApiFactory.SigningKey);

        var response = await RegionsAsync(token);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task A_not_yet_valid_token_is_rejected()
    {
        var token = JwtApiFactory.IssueToken(
            roles: ["Mina.Analyst"],
            notBefore: DateTime.UtcNow.AddHours(1),
            expires: DateTime.UtcNow.AddHours(2),
            signingKey: JwtApiFactory.SigningKey);

        var response = await RegionsAsync(token);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task A_token_signed_by_a_key_the_api_does_not_trust_is_rejected()
    {
        // Correct issuer, audience, claims, lifetime -- everything except the actual signature,
        // which is the one thing that proves a token came from something holding the real key.
        var token = JwtApiFactory.IssueToken(roles: ["Mina.Analyst"], signingKey: JwtApiFactory.OtherKey);

        var response = await RegionsAsync(token);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task An_unsigned_token_is_rejected()
    {
        var token = JwtApiFactory.IssueToken(roles: ["Mina.Analyst"], signingKey: null);

        var response = await RegionsAsync(token);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task A_token_tampered_after_signing_is_rejected()
    {
        // A byte-level flip of the payload's *last* character corrupts the JSON's closing brace and
        // never reaches signature checking at all -- the token simply fails to parse (IDX14101),
        // caught only by actually inspecting IdentityModel's own diagnostics rather than trusting
        // that a 401 meant what this test intended. Decoding, editing a claim *value*, and
        // re-encoding keeps the JSON structurally valid, so a 401 here can only come from the
        // signature no longer matching the (still well-formed, still parseable) content it was
        // computed over.
        var token = JwtApiFactory.IssueToken(oid: "oid-tamper-1", roles: ["Mina.Analyst"], signingKey: JwtApiFactory.SigningKey);
        var parts = token.Split('.');
        Assert.Equal(3, parts.Length); // header.payload.signature -- fail loud if the shape assumed here ever changes

        var payloadJson = System.Text.Encoding.UTF8.GetString(Base64UrlDecode(parts[1]));
        Assert.Contains("oid-tamper-1", payloadJson, StringComparison.Ordinal); // fail loud if the claim moved
        var tamperedJson = payloadJson.Replace("oid-tamper-1", "oid-tamper-2", StringComparison.Ordinal);
        var tampered = string.Join('.', parts[0], Base64UrlEncode(System.Text.Encoding.UTF8.GetBytes(tamperedJson)), parts[2]);

        var response = await RegionsAsync(tampered);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task A_role_claim_added_after_signing_does_not_grant_access()
    {
        // The most concrete version of "tampered token": no roles at all when signed, then a
        // Mina.Admin role spliced into the decoded claims the way a client-side or proxy-layer bug
        // might. Asserted as 401, not 403: a forged token like this should never reach the role
        // check at all -- signature validation is authentication, and failing it is an
        // authentication failure, not an authorization decision the app got to make.
        var noRoles = JwtApiFactory.IssueToken(roles: [], signingKey: JwtApiFactory.SigningKey);
        var parts = noRoles.Split('.');

        var payloadJson = System.Text.Encoding.UTF8.GetString(
            Base64UrlDecode(parts[1]));
        // Replace only the closing brace of the top-level object, not every "}" in the payload --
        // today's claim set is flat, but this stays correct if that ever changes.
        var lastBrace = payloadJson.LastIndexOf('}');
        var withAdminRole = payloadJson[..lastBrace] + ",\"roles\":[\"Mina.Admin\"]" + payloadJson[lastBrace..];
        var forgedPayload = Base64UrlEncode(System.Text.Encoding.UTF8.GetBytes(withAdminRole));
        var forged = string.Join('.', parts[0], forgedPayload, parts[2]);

        var response = await BearerClient(forged).GetAsync(new Uri("/api/audit/recent", UriKind.Relative));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode); // signature check fails before role check runs
    }

    private static byte[] Base64UrlDecode(string input)
    {
        var padded = input.Replace('-', '+').Replace('_', '/');
        padded += new string('=', (4 - padded.Length % 4) % 4);
        return Convert.FromBase64String(padded);
    }

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=');
}
