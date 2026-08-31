using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Mvc;
using Mina.ControlPlane.Application.Sessions;
using Mina.ControlPlane.Domain.Regions;
using Mina.ControlPlane.Domain.Sessions;

namespace Mina.ControlPlane.Api.Sessions;

public sealed record IssueSessionDto(string Region, string CsrPem);

public sealed record RenewSessionDto(string CsrPem);

public sealed record SessionResponseDto(
    Guid SessionId,
    string CertificatePem,
    string CertificateSerialNumber,
    string Region,
    string EgressHost,
    int EgressPort,
    string EgressServerName,
    DateTimeOffset LeaseExpiresAt,
    string Mode);

/// <summary>
/// Session management endpoints (M2-2). All require the analyst app role (enforced by the
/// "MinaAnalyst" authorization policy) and derive identity from the validated Entra token, never
/// from the request body. Authorisation denials map to 403, a missing session to 404, and a
/// malformed CSR to 400.
/// </summary>
public static class SessionEndpoints
{
    public const string AnalystPolicy = "MinaAnalyst";
    private const string CsrPemLabel = "CERTIFICATE REQUEST";

    public static IEndpointRouteBuilder MapMinaSessionEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/api/regions", (RegionPolicy regions) =>
                Results.Ok(new { regions = regions.SelectableRegions }))
            .RequireAuthorization(AnalystPolicy);

        var group = app.MapGroup("/api/sessions").RequireAuthorization(AnalystPolicy);

        group.MapPost("/", IssueAsync);
        group.MapPost("/{id:guid}/renew", RenewAsync);
        group.MapDelete("/{id:guid}", EndAsync);

        return app;
    }

    private static async Task<IResult> IssueAsync(
        IssueSessionDto dto, ClaimsPrincipal user, SessionService sessions, CancellationToken ct)
    {
        if (!TryDecodeCsr(dto.CsrPem, out var csr))
        {
            return Results.Problem("Body must contain a PEM certificate signing request.", statusCode: 400);
        }

        return await ExecuteAsync(async () =>
        {
            var grant = await sessions.IssueAsync(user.ToSessionPrincipal(), new SessionIssueRequest(dto.Region, csr), ct);
            return Results.Created($"/api/sessions/{grant.SessionId}", ToResponse(grant));
        });
    }

    private static async Task<IResult> RenewAsync(
        Guid id, RenewSessionDto dto, ClaimsPrincipal user, SessionService sessions, CancellationToken ct)
    {
        if (!TryDecodeCsr(dto.CsrPem, out var csr))
        {
            return Results.Problem("Body must contain a PEM certificate signing request.", statusCode: 400);
        }

        return await ExecuteAsync(async () =>
        {
            var grant = await sessions.RenewAsync(user.ToSessionPrincipal(), id, csr, ct);
            return Results.Ok(ToResponse(grant));
        });
    }

    private static async Task<IResult> EndAsync(
        Guid id, ClaimsPrincipal user, SessionService sessions, CancellationToken ct)
    {
        return await ExecuteAsync(async () =>
        {
            await sessions.EndAsync(user.ToSessionPrincipal(), id, SessionEndReason.EndedByUser, ct);
            return Results.NoContent();
        });
    }

    private static async Task<IResult> ExecuteAsync(Func<Task<IResult>> action)
    {
        try
        {
            return await action();
        }
        catch (SessionAuthorizationException ex)
        {
            return ex.Reason switch
            {
                SessionDenialReason.SessionNotFound => Results.NotFound(),
                SessionDenialReason.InvalidCertificateRequest =>
                    Results.Problem(ex.Message, statusCode: StatusCodes.Status400BadRequest),
                _ => Results.Problem(
                    $"Denied: {ex.Reason}", statusCode: StatusCodes.Status403Forbidden),
            };
        }
        catch (SessionStateException ex)
        {
            // The session exists but is no longer in a state that allows this — ended, revoked or
            // expired. That is the caller's situation, not a server fault: answering 409 keeps it
            // out of the error budget and tells the agent to establish a new session instead.
            return Results.Problem(ex.Message, statusCode: StatusCodes.Status409Conflict);
        }
    }

    private static SessionResponseDto ToResponse(SessionGrant grant)
    {
        using var cert = X509CertificateLoader.LoadCertificate(grant.IssuedCertificate);
        return new SessionResponseDto(
            grant.SessionId,
            cert.ExportCertificatePem(),
            grant.CertificateSerialNumber,
            grant.Region,
            grant.Egress.Host,
            grant.Egress.Port,
            grant.Egress.ServerName,
            grant.LeaseExpiresAt,
            grant.Mode.ToString());
    }

    private static bool TryDecodeCsr(string? csrPem, out byte[] der)
    {
        der = [];
        if (string.IsNullOrWhiteSpace(csrPem) || !PemEncoding.TryFind(csrPem, out var fields))
        {
            return false;
        }

        if (!csrPem.AsSpan()[fields.Label].SequenceEqual(CsrPemLabel))
        {
            return false;
        }

        try
        {
            // Convert.FromBase64String ignores the newlines within the PEM body.
            der = Convert.FromBase64String(csrPem[fields.Base64Data]);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
