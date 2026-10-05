// IP echo canary (TEST_STRATEGY §2): returns what a remote site observes about the caller.
// Deployed OUTSIDE the Mina platform; leak tests assert the research context surfaces the
// approved Azure egress IP (AC-003) and ordinary applications surface corporate egress (AC-002).

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapGet("/healthz", () => Results.Ok(new { status = "ok", component = "mina-canary-ipecho" }));

app.MapGet("/", (HttpContext context) => Results.Json(new
{
    observed_at_utc = DateTimeOffset.UtcNow,
    source_ip = context.Connection.RemoteIpAddress?.ToString(),
    source_port = context.Connection.RemotePort,
    x_forwarded_for = context.Request.Headers["X-Forwarded-For"].ToString(),
    user_agent = context.Request.Headers.UserAgent.ToString(),
    host_header = context.Request.Host.Value,
}));

app.Run();
