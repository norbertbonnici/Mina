using System.Net;
using System.Net.Sockets;
using Grpc.Net.Client;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Mina.EgressNode.Sidecar;
using Mina.EgressNode.Sidecar.Envoy;

namespace Mina.EgressNode.Sidecar.Tests;

/// <summary>
/// The admission socket as Envoy uses it: a real Kestrel on a real Unix socket, spoken to with
/// the same gRPC service Envoy's ext_authz calls. The unit tests cover the decision; these cover
/// that the decision is reachable on the socket and nowhere else, that the wire answer is exactly
/// OK or exactly not, and that a session issued since the last refresh is admitted on its first
/// tunnel rather than after the next poll.
/// </summary>
public sealed class SessionAdmissionHostTests : IAsyncLifetime
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 2, 9, 0, 0, TimeSpan.Zero);

    private readonly string _socketDirectory = Path.Combine(Path.GetTempPath(), "mina-adm-" + Guid.NewGuid().ToString("N")[..8]);
    private readonly TestClock _clock = new(T0);
    private readonly NodeSessionView _view = new();
    private readonly ScriptedRefresher _refresher = new();
    private WebApplication _app = null!;

    private string SocketPath => Path.Combine(_socketDirectory, "authz.sock");

    public async Task InitializeAsync()
    {
        Directory.CreateDirectory(_socketDirectory);

        var builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.Services.AddSingleton<TimeProvider>(_clock);
        builder.Services.AddSingleton(_view);
        builder.Services.AddSingleton<ISessionViewRefresher>(_refresher);
        builder.Services.AddSingleton(Options.Create(new SidecarOptions
        {
            Region = "westeurope",
            ControlPlaneBaseAddress = new Uri("https://control.invalid/"),
            AuthzSocketPath = SocketPath,
            AllowlistRefreshInterval = TimeSpan.FromSeconds(15),
            AdmissionMaxViewAge = TimeSpan.FromMinutes(5),
        }));
        builder.AddSessionAdmissionListener(SocketPath);

        _app = builder.Build();
        _app.UseSessionAdmission();
        await _app.StartAsync();
    }

    public async Task DisposeAsync()
    {
        await _app.StopAsync();
        await _app.DisposeAsync();
        try
        {
            Directory.Delete(_socketDirectory, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    [Fact]
    public async Task A_listed_session_is_admitted()
    {
        var session = Guid.NewGuid();
        _view.Update([new NodeSession(session, false, T0.AddMinutes(45))], _clock);

        var response = await CheckAsync($"mina:session:{session}");

        Assert.Equal(0, response.Status.Code);
        Assert.NotNull(response.OkResponse);
    }

    [Fact]
    public async Task A_revoked_session_is_refused_after_the_next_refresh()
    {
        var session = Guid.NewGuid();
        _view.Update([new NodeSession(session, false, T0.AddMinutes(45))], _clock);
        Assert.Equal(0, (await CheckAsync($"mina:session:{session}")).Status.Code);

        _clock.Now = T0.AddSeconds(15);
        _view.Update([], _clock);

        var refused = await CheckAsync($"mina:session:{session}");
        Assert.NotEqual(0, refused.Status.Code);
        Assert.Equal(StatusCode.Forbidden, refused.DeniedResponse.Status.Code);
    }

    [Fact]
    public async Task A_principal_that_is_not_a_session_is_refused()
    {
        _view.Update([new NodeSession(Guid.NewGuid(), false, T0.AddMinutes(45))], _clock);

        Assert.NotEqual(0, (await CheckAsync("CN=someone,O=Elsewhere")).Status.Code);
        Assert.NotEqual(0, (await CheckAsync(string.Empty)).Status.Code);
        Assert.False(_refresher.Called, "an unreadable principal must not trigger a control-plane refresh");
    }

    [Fact]
    public async Task Before_the_first_refresh_everything_is_refused()
    {
        Assert.NotEqual(0, (await CheckAsync($"mina:session:{Guid.NewGuid()}")).Status.Code);
    }

    [Fact]
    public async Task A_stale_view_refuses_even_a_listed_session()
    {
        var session = Guid.NewGuid();
        _view.Update([new NodeSession(session, false, T0.AddHours(1))], _clock);
        _clock.Now = T0.AddMinutes(6);

        Assert.NotEqual(0, (await CheckAsync($"mina:session:{session}")).Status.Code);
    }

    [Fact]
    public async Task A_session_issued_since_the_last_refresh_is_admitted_on_its_first_tunnel()
    {
        // The cold-start case. Without a refresh on miss the analyst's first page loads fail for up
        // to one poll interval after every session start, and the helpdesk reads it as a fault.
        var newSession = Guid.NewGuid();
        _view.Update([new NodeSession(Guid.NewGuid(), false, T0.AddMinutes(45))], _clock);
        _refresher.OnRefresh = () =>
            _view.Update([new NodeSession(newSession, false, T0.AddMinutes(45))], _clock);

        var response = await CheckAsync($"mina:session:{newSession}");

        Assert.Equal(0, response.Status.Code);
        Assert.Equal(1, _refresher.Calls);
    }

    [Fact]
    public async Task A_session_that_stays_unknown_after_the_refresh_is_refused_and_not_refreshed_again_within_the_interval()
    {
        _view.Update([], _clock);
        var unknown = Guid.NewGuid();

        Assert.NotEqual(0, (await CheckAsync($"mina:session:{unknown}")).Status.Code);
        Assert.NotEqual(0, (await CheckAsync($"mina:session:{unknown}")).Status.Code);
        Assert.NotEqual(0, (await CheckAsync($"mina:session:{unknown}")).Status.Code);

        // Three attempts, one control-plane call: a certificate for a session that will never be
        // listed cannot turn every tunnel attempt into a request upstream.
        Assert.Equal(1, _refresher.Calls);
    }

    [Fact]
    public async Task A_refresh_on_miss_that_does_not_return_in_time_still_gets_an_answer()
    {
        _view.Update([], _clock);
        _refresher.Delay = TimeSpan.FromSeconds(30);

        using var overall = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var response = await CheckAsync($"mina:session:{Guid.NewGuid()}", overall.Token);

        Assert.NotEqual(0, response.Status.Code);
    }

    [Fact]
    public async Task Health_reports_the_view_not_the_process()
    {
        // Envoy's active health check, and through it the load balancer's. A running sidecar with
        // nothing to admit is not healthy — that is precisely the node that must leave rotation.
        Assert.Equal(HttpStatusCode.ServiceUnavailable, (await HealthAsync()).StatusCode);

        _view.Update([], _clock);
        Assert.Equal(HttpStatusCode.OK, (await HealthAsync()).StatusCode);

        _clock.Now = T0.AddMinutes(6);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, (await HealthAsync()).StatusCode);
    }

    [Fact]
    public void The_host_listens_on_the_socket_and_on_no_network_address()
    {
        Assert.All(_app.Urls, a => Assert.StartsWith("http://unix:", a, StringComparison.OrdinalIgnoreCase));
        Assert.True(File.Exists(SocketPath), "the admission socket was not created");
    }

    private async Task<CheckResponse> CheckAsync(string principal, CancellationToken cancellationToken = default)
    {
        using var channel = GrpcChannel.ForAddress("http://mina-sidecar", new GrpcChannelOptions { HttpHandler = Handler() });
        var client = new Mina.EgressNode.Sidecar.Envoy.Authorization.AuthorizationClient(channel);
        var request = new CheckRequest
        {
            Attributes = new AttributeContext
            {
                Source = new AttributeContext.Types.Peer { Principal = principal },
                Request = new AttributeContext.Types.Request
                {
                    Http = new AttributeContext.Types.HttpRequest { Method = "CONNECT", Host = "example.test:443" },
                },
            },
        };
        return await client.CheckAsync(request, cancellationToken: cancellationToken);
    }

    private async Task<HttpResponseMessage> HealthAsync()
    {
        using var http = new HttpClient(Handler())
        {
            DefaultRequestVersion = HttpVersion.Version20,
            DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact,
        };
        return await http.GetAsync(new Uri("http://mina-sidecar/healthz"));
    }

    private SocketsHttpHandler Handler() => new()
    {
        ConnectCallback = async (_, ct) =>
        {
            var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            await socket.ConnectAsync(new UnixDomainSocketEndPoint(SocketPath), ct);
            return new NetworkStream(socket, ownsSocket: true);
        },
    };

    private sealed class ScriptedRefresher : ISessionViewRefresher
    {
        public int Calls { get; private set; }

        public bool Called => Calls > 0;

        public Action? OnRefresh { get; set; }

        public TimeSpan Delay { get; set; }

        public async Task RefreshAsync(CancellationToken cancellationToken)
        {
            Calls++;
            if (Delay > TimeSpan.Zero)
            {
                await Task.Delay(Delay, cancellationToken);
            }

            OnRefresh?.Invoke();
        }
    }
}
