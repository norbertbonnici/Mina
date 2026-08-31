// Mina control-plane API — M0 skeleton.
// M2-2 adds Entra token validation, session issuance/renewal and region policy;
// M3 adds the sensitive-session workflow and audit pipeline. Nothing is stubbed to
// look implemented: endpoints appear when their milestone lands.

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapGet("/healthz", () => Results.Ok(new { status = "ok", component = "mina-control-plane-api" }));

app.Run();
