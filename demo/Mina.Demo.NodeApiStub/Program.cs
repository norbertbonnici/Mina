// Node-API stub — DEVELOPMENT ONLY, NOT THE CONTROL PLANE.
//
// Stands in for the two control-plane endpoints an egress node's sidecar calls
// (Mina.ControlPlane.Api's NodeEndpoints: GET /api/nodes/{region}/sessions, POST
// /api/nodes/telemetry), plus an /admin surface to add and revoke sessions interactively.
//
// This exists because the real control-plane API validates real Entra bearer tokens and has no
// bypass in it (by design — see demo/README.md), so it cannot be reached from another process
// without a tenant. This stub does not replace it or exercise its authorization, session-service,
// or audit logic at all — only the wire shape the sidecar depends on, for testing the real Envoy +
// real sidecar admission wiring (M4-11) in isolation. Never deployed; lives only in
// demo/docker-stack. Console output, not ILogger: this is a manual-testing aid, not shipped code.

using System.Collections.Concurrent;

var builder = WebApplication.CreateBuilder(args);
builder.Logging.ClearProviders();
var app = builder.Build();

Console.WriteLine("Node-API stub listening. Not the control plane — see the header of Program.cs.");

// SessionId -> (Suppressed, LeaseExpiresAt). No auth, no region scoping, no persistence: a stub,
// not a security boundary.
var sessions = new ConcurrentDictionary<Guid, (bool Suppressed, DateTimeOffset LeaseExpiresAt)>();

app.MapGet("/healthz", () => Results.Text("ok"));

app.MapGet("/api/nodes/{region}/sessions", (string region) =>
{
    var now = DateTimeOffset.UtcNow;
    var live = sessions
        .Where(kv => kv.Value.LeaseExpiresAt > now)
        .Select(kv => new { sessionId = kv.Key, suppressed = kv.Value.Suppressed, leaseExpiresAt = kv.Value.LeaseExpiresAt })
        .ToList();
    Console.WriteLine($"[sessions] {region}: {live.Count} live of {sessions.Count} known");
    return Results.Json(live);
});

app.MapPost("/api/nodes/telemetry", async (HttpRequest request) =>
{
    var body = await request.ReadFromJsonAsync<TelemetryBatch>();
    var items = body?.Items ?? [];
    foreach (var item in items)
    {
        Console.WriteLine(item.Hostname is null
            ? $"[telemetry] session {item.SessionId}: (withheld — suppressed or unadmitted)"
            : $"[telemetry] session {item.SessionId}: {item.Hostname}:{item.Port}");
    }

    return Results.Json(new { recorded = items.Count, aggregated = 0, unattributable = 0, suppressionMismatches = 0 });
});

app.MapGet("/admin/sessions", () =>
{
    var now = DateTimeOffset.UtcNow;
    return Results.Json(sessions.Select(kv => new
    {
        sessionId = kv.Key,
        suppressed = kv.Value.Suppressed,
        leaseExpiresAt = kv.Value.LeaseExpiresAt,
        live = kv.Value.LeaseExpiresAt > now,
    }));
});

app.MapPost("/admin/sessions", (AdminAdmitRequest body) =>
{
    var leaseMinutes = body.LeaseMinutes ?? 60;
    var expires = DateTimeOffset.UtcNow.AddMinutes(leaseMinutes);
    sessions[body.SessionId] = (body.Suppressed ?? false, expires);
    Console.WriteLine($"[admin] ADMITTED session {body.SessionId} (suppressed={body.Suppressed ?? false}, lease {leaseMinutes}m)");
    return Results.Ok(new { sessionId = body.SessionId, leaseExpiresAt = expires });
});

app.MapDelete("/admin/sessions/{id:guid}", (Guid id) =>
{
    var removed = sessions.TryRemove(id, out _);
    Console.WriteLine(removed
        ? $"[admin] REVOKED session {id}"
        : $"[admin] session {id} was not known — nothing to revoke");
    return removed ? Results.Ok() : Results.NotFound();
});

app.MapPost("/admin/sessions/clear", () =>
{
    var count = sessions.Count;
    sessions.Clear();
    Console.WriteLine($"[admin] cleared {count} session(s)");
    return Results.Ok(new { cleared = count });
});

app.Run();

internal sealed record AdminAdmitRequest(Guid SessionId, bool? Suppressed, int? LeaseMinutes);

internal sealed record TelemetryItemDto(Guid SessionId, DateTimeOffset OccurredAt, string? Hostname, int Port, long BytesUp, long BytesDown, int DurationMs);

internal sealed record TelemetryBatch(string Region, List<TelemetryItemDto> Items);
