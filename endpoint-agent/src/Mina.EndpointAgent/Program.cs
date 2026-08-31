// Mina endpoint agent — M0 skeleton.
// M1-4 (PoC) adds: WAM-broker authentication, the loopback proxy, and the mTLS HTTP/2 tunnel
// client. M2-4 hardens it into the production service (WFP rules, named-pipe IPC, tamper
// telemetry) per ARCHITECTURE §3.1.

using Mina.EndpointAgent;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = "MinaEndpointAgent");
builder.Services.AddHostedService<AgentWorker>();

var host = builder.Build();
host.Run();
