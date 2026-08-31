using System.Net;
using System.Net.Sockets;
using System.Text;
using Mina.EndpointAgent.Proxy;
using Mina.EndpointAgent.Session;

namespace Mina.Agent.E2E.Tests;

/// <summary>
/// The full analyst path, end to end and in process:
/// agent authenticates → control plane authorises (role, device, region) and signs the endpoint's
/// CSR → agent opens an mTLS tunnel with that certificate → research browser reaches the target
/// through the egress. And the property that matters most: when there is no session, there is no
/// path out (AC-004).
/// </summary>
public sealed class AgentEndToEndTests
{
    [Fact]
    public async Task Analyst_browses_through_the_full_stack()
    {
        await using var env = MinaTestEnvironment.Create();

        var session = await env.Sessions.EstablishAsync(default);
        var proxy = env.StartProxy();

        var echoed = await BrowseAsync(proxy, env.ResearchTarget, "hello-from-the-analyst");

        Assert.Equal("hello-from-the-analyst", echoed);
        Assert.Equal("westeurope", session.Region);
        Assert.NotEqual(Guid.Empty, session.SessionId);

        // The traffic really went through the egress, which saw only the hostname:port it was asked
        // to reach — the same plaintext authority the real egress records as telemetry.
        Assert.Contains(env.ResearchTarget.ToString(), env.Egress.ObservedAuthorities);
    }

    [Fact]
    public async Task With_no_session_the_proxy_fails_closed()
    {
        await using var env = MinaTestEnvironment.Create();

        // Proxy is up but no session was established.
        var proxy = env.StartProxy();
        var status = await ConnectStatusAsync(proxy, env.ResearchTarget);

        Assert.Equal(502, status);
        Assert.Empty(env.Egress.ObservedAuthorities);
    }

    [Fact]
    public async Task Ending_the_session_closes_the_protected_path()
    {
        await using var env = MinaTestEnvironment.Create();
        await env.Sessions.EstablishAsync(default);
        var proxy = env.StartProxy();

        Assert.Equal("before", await BrowseAsync(proxy, env.ResearchTarget, "before"));

        await env.Sessions.EndAsync(default);

        Assert.Null(env.Sessions.Current);
        Assert.Equal(502, await ConnectStatusAsync(proxy, env.ResearchTarget));
    }

    [Fact]
    public async Task Renewal_rotates_the_session_certificate_and_traffic_continues()
    {
        // Short lease, generous margin: renewal is due immediately.
        await using var env = MinaTestEnvironment.Create(
            leaseTtl: TimeSpan.FromMinutes(5), renewMargin: TimeSpan.FromMinutes(10));

        var first = await env.Sessions.EstablishAsync(default);
        var proxy = env.StartProxy();
        Assert.Equal("before-renewal", await BrowseAsync(proxy, env.ResearchTarget, "before-renewal"));

        var renewed = await env.Sessions.RenewIfDueAsync(default);

        Assert.True(renewed);
        var current = env.Sessions.Current;
        Assert.NotNull(current);
        Assert.Equal(first.SessionId, current.SessionId);                        // same session…
        Assert.NotEqual(first.CertificateSerialNumber, current.CertificateSerialNumber); // …new credential
        Assert.True(current.LeaseExpiresAt > first.LeaseExpiresAt);

        Assert.Equal("after-renewal", await BrowseAsync(proxy, env.ResearchTarget, "after-renewal"));
    }

    [Fact]
    public async Task Renewal_is_skipped_while_the_lease_is_still_fresh()
    {
        await using var env = MinaTestEnvironment.Create(
            leaseTtl: TimeSpan.FromMinutes(60), renewMargin: TimeSpan.FromMinutes(10));

        var first = await env.Sessions.EstablishAsync(default);

        Assert.False(await env.Sessions.RenewIfDueAsync(default));
        Assert.Equal(first.CertificateSerialNumber, env.Sessions.Current!.CertificateSerialNumber);
    }

    [Fact]
    public async Task A_session_ended_elsewhere_fails_the_renewal_closed()
    {
        await using var env = MinaTestEnvironment.Create(
            leaseTtl: TimeSpan.FromMinutes(5), renewMargin: TimeSpan.FromMinutes(10));

        var session = await env.Sessions.EstablishAsync(default);
        var proxy = env.StartProxy();
        Assert.Equal("ok", await BrowseAsync(proxy, env.ResearchTarget, "ok"));

        // The session is ended out of band (an administrator or another device) — the agent still
        // holds a currently-valid certificate and does not know yet.
        await env.CreateSecondClient().EndAsync(session.SessionId, default);

        var renewed = await env.Sessions.RenewIfDueAsync(default);

        Assert.False(renewed);
        Assert.Null(env.Sessions.Current);                                   // dropped, not carried on
        Assert.Equal(502, await ConnectStatusAsync(proxy, env.ResearchTarget));
    }

    [Fact]
    public async Task Renewing_a_session_ended_elsewhere_reports_a_conflict()
    {
        await using var env = MinaTestEnvironment.Create();
        var session = await env.Sessions.EstablishAsync(default);
        var client = env.CreateSecondClient();
        await client.EndAsync(session.SessionId, default);

        using var key = new SessionKeyMaterial();
        var ex = await Assert.ThrowsAsync<ControlPlaneException>(
            () => client.RenewAsync(session.SessionId, key.CreateCertificateSigningRequest(), default));

        // A caller-side condition, so the control plane answers 409 rather than failing internally.
        Assert.Equal(HttpStatusCode.Conflict, ex.StatusCode);
    }

    [Fact]
    public async Task An_inactive_region_is_refused_and_leaves_no_session()
    {
        // francecentral is on the approved list but has no active stamp (AC-008).
        await using var env = MinaTestEnvironment.Create(region: "francecentral");

        var ex = await Assert.ThrowsAsync<ControlPlaneException>(() => env.Sessions.EstablishAsync(default));

        Assert.Equal(HttpStatusCode.Forbidden, ex.StatusCode);
        Assert.Null(env.Sessions.Current);
        Assert.Equal(502, await ConnectStatusAsync(env.StartProxy(), env.ResearchTarget));
    }

    [Fact]
    public async Task A_caller_without_the_analyst_role_gets_no_session()
    {
        await using var env = MinaTestEnvironment.Create(roles: "Mina.Approver");

        var ex = await Assert.ThrowsAsync<ControlPlaneException>(() => env.Sessions.EstablishAsync(default));

        Assert.Equal(HttpStatusCode.Forbidden, ex.StatusCode);
        Assert.Null(env.Sessions.Current);
    }

    [Fact]
    public async Task A_noncompliant_device_gets_no_session()
    {
        await using var env = MinaTestEnvironment.Create(device: null);

        var ex = await Assert.ThrowsAsync<ControlPlaneException>(() => env.Sessions.EstablishAsync(default));

        Assert.Equal(HttpStatusCode.Forbidden, ex.StatusCode);
        Assert.Null(env.Sessions.Current);
    }

    private static async Task<string> BrowseAsync(IPEndPoint proxy, ConnectTarget target, string payload)
    {
        using var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
        await socket.ConnectAsync(proxy);
        await using var stream = new NetworkStream(socket, ownsSocket: false);

        await stream.WriteAsync(HttpConnect.BuildConnectRequest(target));
        Assert.Equal(200, await HttpConnect.ReadResponseStatusAsync(stream, CancellationToken.None));

        var bytes = Encoding.UTF8.GetBytes(payload);
        await stream.WriteAsync(bytes);

        var received = new byte[bytes.Length];
        var offset = 0;
        while (offset < received.Length)
        {
            var read = await stream.ReadAsync(received.AsMemory(offset));
            if (read == 0)
            {
                break;
            }

            offset += read;
        }

        return Encoding.UTF8.GetString(received, 0, offset);
    }

    private static async Task<int> ConnectStatusAsync(IPEndPoint proxy, ConnectTarget target)
    {
        using var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
        await socket.ConnectAsync(proxy);
        await using var stream = new NetworkStream(socket, ownsSocket: false);

        await stream.WriteAsync(HttpConnect.BuildConnectRequest(target));
        return await HttpConnect.ReadResponseStatusAsync(stream, CancellationToken.None);
    }
}
