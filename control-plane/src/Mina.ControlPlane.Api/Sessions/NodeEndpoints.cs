using Mina.ControlPlane.Application.Telemetry;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using Mina.ControlPlane.Api.Configuration;
using Mina.ControlPlane.Api.Infrastructure;
using Mina.ControlPlane.Domain.Regions;
using Mina.ControlPlane.Pki;
using Mina.Observability;

using Mina.ControlPlane.Hosting;

namespace Mina.ControlPlane.Api.Sessions;

public sealed record NodeSessionDto(Guid SessionId, bool Suppressed, DateTimeOffset LeaseExpiresAt);

/// <summary>Response to a node's server-certificate request (M2-2d).</summary>
/// <param name="CertificatePem">The signed server certificate, PEM, no private key.</param>
/// <param name="CaCertificatePem">
/// The CA's own public certificate, PEM. Handed back here rather than fetched by the node
/// separately from Key Vault: the node already holds an authenticated channel to this API, so
/// reusing it avoids granting every node's managed identity Key Vault read access just to learn a
/// certificate that is public material to begin with.
/// </param>
public sealed record NodeCertificateDto(string CertificatePem, string CaCertificatePem);

public sealed record TelemetryItemDto(
    Guid SessionId,
    DateTimeOffset OccurredAt,
    string? Hostname,
    int Port,
    long BytesUp,
    long BytesDown,
    int DurationMs);

public sealed record TelemetryBatchDto(string Region, IReadOnlyList<TelemetryItemDto> Items);

public sealed record TelemetryAcceptedDto(
    int Recorded, int Aggregated, int Unattributable, int SuppressionMismatches, int Rejected);

/// <summary>
/// The egress nodes' interface to the control plane: which sessions to serve, and where their
/// hostname telemetry goes. Nodes authenticate with their own managed identity and hold the node
/// app role, plus a per-region grant (<c>Mina.Node.&lt;region&gt;</c>). An analyst token cannot
/// reach these at all, and a node cannot read or write for a region it was not granted.
/// </summary>
public static class NodeEndpoints
{
    public const string NodePolicy = "MinaNode";

    public static IEndpointRouteBuilder MapMinaNodeEndpoints(
        this IEndpointRouteBuilder app, MinaListener listener)
    {
        var group = app.MapGroup("/api/nodes").RequireAuthorization(NodePolicy).RequireListener(listener);

        group.MapGet("/{region}/sessions", async (
            string region, ClaimsPrincipal node, NodeDirectoryService directory, CancellationToken ct) =>
        {
            if (!RegionName.IsWellFormed(region))
            {
                return Results.Problem(
                    "A well-formed region is required.", statusCode: StatusCodes.Status400BadRequest);
            }

            // Being a node is not enough: the caller must be *this* region's node.
            if (!NodeRegionGrant.IsGrantedFor(node, region))
            {
                return Results.Problem(
                    $"This node is not granted region '{region}'.", statusCode: StatusCodes.Status403Forbidden);
            }

            var entries = await directory.ListAsync(region, ct);
            return Results.Ok(entries.Select(e => new NodeSessionDto(e.SessionId, e.Suppressed, e.LeaseExpiresAt)));
        });

        group.MapPost("/telemetry", async (
            TelemetryBatchDto dto, ClaimsPrincipal node, TelemetryIngestService ingest,
            MinaMetrics metrics, CancellationToken ct) =>
        {
            // Same reasoning as session issuance: the region becomes a metric dimension and an
            // audit field, so it is bounded before either sees it.
            if (!RegionName.IsWellFormed(dto.Region))
            {
                return Results.Problem(
                    "A well-formed region is required.", statusCode: StatusCodes.Status400BadRequest);
            }

            if (!NodeRegionGrant.IsGrantedFor(node, dto.Region))
            {
                return Results.Problem(
                    $"This node is not granted region '{dto.Region}'.", statusCode: StatusCodes.Status403Forbidden);
            }

            var batch = new TelemetryBatch(dto.Region, [.. dto.Items.Select(i => new TelemetryItem(
                i.SessionId, i.OccurredAt, i.Hostname, i.Port, i.BytesUp, i.BytesDown, i.DurationMs))]);

            var result = await ingest.IngestAsync(batch, ct);

            metrics.TelemetryIngested(dto.Region, "recorded", result.Recorded);
            metrics.TelemetryIngested(dto.Region, "aggregated", result.Aggregated);
            metrics.TelemetryIngested(dto.Region, "unattributable", result.Unattributable);
            metrics.TelemetryIngested(dto.Region, "rejected", result.Rejected);
            if (result.SuppressionMismatches > 0)
            {
                metrics.SuppressionMismatch(dto.Region, result.SuppressionMismatches);
            }

            // The node is told what happened, including that it sent destinations it should have
            // withheld — a node with a stale allowlist can then correct itself. The control plane
            // has already discarded them either way.
            return Results.Ok(new TelemetryAcceptedDto(
                result.Recorded, result.Aggregated, result.Unattributable, result.SuppressionMismatches,
                result.Rejected));
        });

        // M2-2d: the last thing standing between a booted node and one that actually serves
        // tunnels. A node generates its own key pair and CSR (the private key never reaches this
        // process) and authenticates the request the same way it authenticates everything else —
        // its own managed identity, region-granted. The SAN is this region's own configured
        // ServerName, never the requester's: a compromised node asking for a certificate naming
        // some other Mina host is refused by construction, not by policy.
        group.MapPost("/{region}/certificate", async (
            string region, HttpRequest request, ClaimsPrincipal node,
            NodeCertificateIssuer issuer, ICertificateAuthorityProvider caProvider,
            IOptions<MinaEgressOptions> egressOptions, TimeProvider clock, CancellationToken ct) =>
        {
            if (!RegionName.IsWellFormed(region))
            {
                return Results.Problem(
                    "A well-formed region is required.", statusCode: StatusCodes.Status400BadRequest);
            }

            if (!NodeRegionGrant.IsGrantedFor(node, region))
            {
                return Results.Problem(
                    $"This node is not granted region '{region}'.", statusCode: StatusCodes.Status403Forbidden);
            }

            if (!egressOptions.Value.Regions.TryGetValue(region, out var egress)
                || string.IsNullOrWhiteSpace(egress.ServerName))
            {
                return Results.Problem(
                    $"No egress ingress is configured for region '{region}' "
                    + $"(Mina:Egress:Regions:{region}:ServerName).",
                    statusCode: StatusCodes.Status503ServiceUnavailable);
            }

            using var body = new MemoryStream();
            await request.Body.CopyToAsync(body, ct);
            var csr = body.ToArray();
            if (csr.Length == 0)
            {
                return Results.Problem(
                    "A PKCS#10 certificate signing request body is required.",
                    statusCode: StatusCodes.Status400BadRequest);
            }

            X509Certificate2 certificate;
            try
            {
                certificate = issuer.IssueFromCsr(csr, [egress.ServerName], [], clock.GetUtcNow());
            }
            catch (CryptographicException)
            {
                // Malformed, or a signature that does not verify against the requester's own
                // claimed key — either way this is not a request this CA will act on.
                return Results.Problem(
                    "The certificate signing request could not be verified.",
                    statusCode: StatusCodes.Status400BadRequest);
            }

            using (certificate)
            using (var caCertificate = caProvider.GetAuthority().PublicCertificate)
            {
                return Results.Ok(new NodeCertificateDto(
                    certificate.ExportCertificatePem(), caCertificate.ExportCertificatePem()));
            }
        });

        return app;
    }
}
