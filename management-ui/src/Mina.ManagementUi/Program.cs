// Mina management UI — M0 skeleton. M3-2 replaces this with the Blazor Server application
// (approvals, sessions, health, audit views) behind Entra sign-in and app roles.

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapGet("/healthz", () => Results.Ok(new { status = "ok", component = "mina-management-ui" }));

app.Run();
