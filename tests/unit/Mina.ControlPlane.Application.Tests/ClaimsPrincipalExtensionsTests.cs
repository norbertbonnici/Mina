using System.Security.Claims;
using Mina.ControlPlane.Application.Sessions;

namespace Mina.ControlPlane.Application.Tests;

/// <summary>
/// Projecting the Entra token into a <see cref="SessionPrincipal"/>. The cases that matter are the
/// mapped claim names: Microsoft.Identity.Web validates with inbound claim mapping on, so what
/// arrives in the <see cref="ClaimsPrincipal"/> is not what is in the JWT.
/// </summary>
public class ClaimsPrincipalExtensionsTests
{
    private const string ObjectIdUri = "http://schemas.microsoft.com/identity/claims/objectidentifier";
    private const string DeviceIdUri = "http://schemas.microsoft.com/2012/01/devicecontext/claims/identifier";

    [Fact]
    public void Short_claim_names_project_as_expected()
    {
        var principal = Principal(
            new Claim("oid", "oid-1"),
            new Claim("preferred_username", "analyst@example.org"),
            new Claim("deviceid", "device-1"),
            new Claim("roles", "Mina.Analyst"),
            new Claim("acrs", "c1"));

        var session = principal.ToSessionPrincipal();

        Assert.Equal("oid-1", session.UserObjectId);
        Assert.Equal("device-1", session.DeviceId);
        Assert.True(session.DeviceBound);
        Assert.Contains("Mina.Analyst", session.Roles);
        Assert.Contains("c1", session.AuthenticationContexts!);
    }

    [Fact]
    public void Mapped_claim_names_project_the_same_way()
    {
        // `JwtSecurityTokenHandler.DefaultInboundClaimTypeMap` rewrites oid, deviceid and roles to
        // WS-Federation URIs, and Microsoft.Identity.Web leaves that mapping on. Reading only the
        // short names meant a real Entra token looked like it had no device id at all, so every
        // session was refused as not device-bound while every test passed.
        var principal = Principal(
            new Claim(ObjectIdUri, "oid-1"),
            new Claim("preferred_username", "analyst@example.org"),
            new Claim(DeviceIdUri, "device-1"),
            new Claim(ClaimTypes.Role, "Mina.Analyst"),
            new Claim("acrs", "c1"));

        var session = principal.ToSessionPrincipal();

        Assert.Equal("oid-1", session.UserObjectId);
        Assert.Equal("device-1", session.DeviceId);
        Assert.True(session.DeviceBound);
        Assert.Contains("Mina.Analyst", session.Roles);

        // acrs is deliberately absent from the map, so it arrives under its own name either way.
        Assert.Contains("c1", session.AuthenticationContexts!);
    }

    [Fact]
    public void A_token_with_no_device_claim_is_not_device_bound()
    {
        var session = Principal(
            new Claim("oid", "oid-1"),
            new Claim("preferred_username", "analyst@example.org")).ToSessionPrincipal();

        Assert.False(session.DeviceBound);
        Assert.Null(session.DeviceId);
        Assert.Empty(session.AuthenticationContexts!);
    }

    private static ClaimsPrincipal Principal(params Claim[] claims) =>
        new(new ClaimsIdentity(claims, "Test", "preferred_username", ClaimTypes.Role));
}
