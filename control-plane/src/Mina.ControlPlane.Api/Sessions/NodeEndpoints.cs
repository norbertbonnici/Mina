using Mina.ControlPlane.Application.Telemetry;

namespace Mina.ControlPlane.Api.Sessions;

public sealed record NodeSessionDto(Guid SessionId, bool Suppressed, DateTimeOffset LeaseExpiresAt);

public sealed record TelemetryItemDto(
    Guid SessionId,
    DateTimeOffset OccurredAt,
    string? Hostname,
    int Port,
    long BytesUp,
    long BytesDown,
    int DurationMs);

public sealed record TelemetryBatchDto(string Region, IReadOnlyList<TelemetryItemDto> Items);

public sealed record TelemetryAcceptedDto(int Recorded, int Aggregated, int Unattributable, int SuppressionMismatches);

/// <summary>
/// The egress nodes' interface to the control plane: which sessions to serve, and where their
/// hostname telemetry goes. Nodes authenticate with their own managed identity and hold the node
/// app role — an analyst token cannot reach these, and neither can read another region's sessions
/// beyond what it asks for.
/// </summary>
public static class NodeEndpoints
{
    public const string NodePolicy = "MinaNode";

    public static IEndpointRouteBuilder MapMinaNodeEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/nodes").RequireAuthorization(NodePolicy);

        group.MapGet("/{region}/sessions", async (
            string region, NodeDirectoryService directory, CancellationToken ct) =>
        {
            var entries = await directory.ListAsync(region, ct);
            return Results.Ok(entries.Select(e => new NodeSessionDto(e.SessionId, e.Suppressed, e.LeaseExpiresAt)));
        });

        group.MapPost("/telemetry", async (
            TelemetryBatchDto dto, TelemetryIngestService ingest, CancellationToken ct) =>
        {
            if (string.IsNullOrWhiteSpace(dto.Region))
            {
                return Results.Problem("A region is required.", statusCode: StatusCodes.Status400BadRequest);
            }

            var batch = new TelemetryBatch(dto.Region, [.. dto.Items.Select(i => new TelemetryItem(
                i.SessionId, i.OccurredAt, i.Hostname, i.Port, i.BytesUp, i.BytesDown, i.DurationMs))]);

            var result = await ingest.IngestAsync(batch, ct);

            // The node is told what happened, including that it sent destinations it should have
            // withheld — a node with a stale allowlist can then correct itself. The control plane
            // has already discarded them either way.
            return Results.Ok(new TelemetryAcceptedDto(
                result.Recorded, result.Aggregated, result.Unattributable, result.SuppressionMismatches));
        });

        return app;
    }
}
