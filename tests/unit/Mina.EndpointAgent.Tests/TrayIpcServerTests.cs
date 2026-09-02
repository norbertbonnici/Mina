using System.Globalization;
using System.IO.Pipes;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Mina.EndpointAgent.Configuration;
using Mina.EndpointAgent.Ipc;

namespace Mina.EndpointAgent.Tests;

/// <summary>
/// The transport itself, over a real named pipe. The pipe is the boundary between SYSTEM and the
/// interactive user, so what matters here is that a peer which misbehaves — truncated frames,
/// oversized frames, nonsense, a control that faults — gets a bounded answer and leaves the agent
/// serving everybody else.
/// </summary>
/// <remarks>
/// The DACL these tests cannot exercise is Windows-only; on other platforms .NET backs a named pipe
/// with a Unix-domain socket. What is portable, and what is asserted here, is the framing, the
/// bounds and the failure handling.
/// </remarks>
[Collection(TrayIpcCollectionMarker.Name)]
public sealed class TrayIpcServerTests
{
    private static readonly TimeSpan Patience = TimeSpan.FromSeconds(20);

    // Deliberately shorter than TrayProtocol.ExchangeTimeout (15s): ExchangeAsync wraps every call
    // in its own CancelAfter(ExchangeTimeout), so a connect timeout at or above that value can
    // never fire on its own terms — the exchange-level deadline wins the race first and the
    // caller sees a raw OperationCanceledException instead of the intended AgentUnavailable
    // translation. This is generous for CI (a freshly started server's first accept can be slow to
    // schedule on a loaded Windows runner) without crossing that ceiling. Not used by the one test
    // that specifically asserts the *production* (2s) connect timeout's fast-detection behaviour —
    // that test keeps the default.
    private static readonly TimeSpan ConnectPatience = TimeSpan.FromSeconds(14);

    private static (TrayIpcServer Server, RecordingTrayControl Control, string PipeName) Build(
        Action<RecordingTrayControl>? configure = null)
    {
        var control = new RecordingTrayControl();
        configure?.Invoke(control);

        var pipeName = "mina-test-" + Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture);
        var server = new TrayIpcServer(
            control,
            Options.Create(new MinaAgentOptions()),
            NullLogger<TrayIpcServer>.Instance)
        {
            PipeName = pipeName,
        };

        return (server, control, pipeName);
    }

    [Fact]
    public async Task A_status_request_gets_a_status_back()
    {
        var (server, control, pipeName) = Build();
        using var cts = new CancellationTokenSource(Patience);
        await server.StartAsync(cts.Token);
        try
        {
            await using var client = new TrayIpcClient(pipeName, connectTimeout: ConnectPatience);

            var response = await client.GetStatusAsync(cts.Token);

            Assert.True(response.Ok);
            Assert.Equal(ProtectedPathStates.Protected, response.Status!.State);
            Assert.Equal(TrayOperations.Status, Assert.Single(control.Seen).Op);
        }
        finally
        {
            await server.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task One_connection_carries_many_requests()
    {
        // The tray polls; opening a pipe instance per poll would churn handles on the agent for no
        // reason.
        var (server, control, pipeName) = Build();
        using var cts = new CancellationTokenSource(Patience);
        await server.StartAsync(cts.Token);
        try
        {
            await using var client = new TrayIpcClient(pipeName, connectTimeout: ConnectPatience);

            for (var i = 0; i < 5; i++)
            {
                Assert.True((await client.GetStatusAsync(cts.Token)).Ok);
            }

            Assert.Equal(5, control.Seen.Count);
        }
        finally
        {
            await server.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task Every_operation_reaches_the_control_with_its_arguments()
    {
        var (server, control, pipeName) = Build();
        using var cts = new CancellationTokenSource(Patience);
        await server.StartAsync(cts.Token);
        try
        {
            await using var client = new TrayIpcClient(pipeName, connectTimeout: ConnectPatience);

            await client.SelectRegionAsync("northeurope", cts.Token);
            await client.RequestSensitiveAsync("CASE-2026-0417", 90, cts.Token);
            await client.ActivateSensitiveAsync(cts.Token);
            await client.CancelSensitiveAsync(cts.Token);
            await client.EndSessionAsync(cts.Token);
            await client.ReconnectAsync(cts.Token);

            Assert.Collection(
                control.Seen,
                r => Assert.Equal("northeurope", r.Region),
                r =>
                {
                    Assert.Equal("CASE-2026-0417", r.JustificationReference);
                    Assert.Equal(90, r.Minutes);
                },
                r => Assert.Equal(TrayOperations.ActivateSensitive, r.Op),
                r => Assert.Equal(TrayOperations.CancelSensitive, r.Op),
                r => Assert.Equal(TrayOperations.EndSession, r.Op),
                r => Assert.Equal(TrayOperations.Reconnect, r.Op));
        }
        finally
        {
            await server.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task A_frame_split_across_writes_is_reassembled()
    {
        var (server, _, pipeName) = Build();
        using var cts = new CancellationTokenSource(Patience);
        await server.StartAsync(cts.Token);
        try
        {
            await using var raw = await ConnectRawAsync(pipeName, cts.Token);

            await raw.WriteAsync(Encoding.UTF8.GetBytes("{\"op\":\"sta"), cts.Token);
            await raw.FlushAsync(cts.Token);
            await raw.WriteAsync(Encoding.UTF8.GetBytes("tus\"}\n"), cts.Token);
            await raw.FlushAsync(cts.Token);

            var response = await ReadResponseAsync(raw, cts.Token);

            Assert.True(response.Ok);
        }
        finally
        {
            await server.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task Nonsense_is_refused_without_taking_the_agent_down()
    {
        var (server, _, pipeName) = Build();
        using var cts = new CancellationTokenSource(Patience);
        await server.StartAsync(cts.Token);
        try
        {
            await using (var raw = await ConnectRawAsync(pipeName, cts.Token))
            {
                await raw.WriteAsync(Encoding.UTF8.GetBytes("this is not json\n"), cts.Token);
                await raw.FlushAsync(cts.Token);

                var response = await ReadResponseAsync(raw, cts.Token);

                Assert.False(response.Ok);
                Assert.Equal(TrayErrorCodes.InvalidRequest, response.Code);
            }

            // The instance that served the bad peer is recycled, so the next client is served.
            await using var client = new TrayIpcClient(pipeName, connectTimeout: ConnectPatience);
            Assert.True((await client.GetStatusAsync(cts.Token)).Ok);
        }
        finally
        {
            await server.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task A_frame_that_never_ends_is_cut_off_at_the_limit()
    {
        // Without the cap a local process could grow the agent's read buffer without bound simply
        // by never sending a newline.
        var (server, _, pipeName) = Build();
        using var cts = new CancellationTokenSource(Patience);
        await server.StartAsync(cts.Token);
        try
        {
            await using var raw = await ConnectRawAsync(pipeName, cts.Token);

            var flood = Encoding.UTF8.GetBytes(new string('x', 8 * 1024));
            try
            {
                for (var i = 0; i < 16; i++)
                {
                    await raw.WriteAsync(flood, cts.Token);
                    await raw.FlushAsync(cts.Token);
                }

                // Every write landed, so the agent must have refused rather than kept buffering.
                var response = await ReadResponseAsync(raw, cts.Token);
                Assert.False(response.Ok);
                Assert.Equal(TrayErrorCodes.InvalidRequest, response.Code);
            }
            catch (IOException)
            {
                // Or it hung up mid-flood, which is the same outcome: the peer does not get to hold
                // the agent open by withholding a newline.
            }

            await using var next = new TrayIpcClient(pipeName, connectTimeout: ConnectPatience);
            Assert.True((await next.GetStatusAsync(cts.Token)).Ok);
        }
        finally
        {
            await server.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task A_faulting_operation_answers_without_leaking_the_fault()
    {
        // The peer is a user-mode process. Exception text can name internal paths and
        // configuration, so it goes to the agent's log and the tray gets a code.
        var (server, _, pipeName) = Build(c =>
            c.Respond = _ => throw new InvalidOperationException("secret internal detail"));

        using var cts = new CancellationTokenSource(Patience);
        await server.StartAsync(cts.Token);
        try
        {
            await using var client = new TrayIpcClient(pipeName, connectTimeout: ConnectPatience);

            var response = await client.GetStatusAsync(cts.Token);

            Assert.False(response.Ok);
            Assert.Equal(TrayErrorCodes.AgentFault, response.Code);
            Assert.DoesNotContain("secret internal detail", response.Error, StringComparison.Ordinal);
        }
        finally
        {
            await server.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task Several_trays_are_served_at_once()
    {
        var (server, control, pipeName) = Build();
        using var cts = new CancellationTokenSource(Patience);
        await server.StartAsync(cts.Token);
        try
        {
            await using var first = new TrayIpcClient(pipeName, connectTimeout: ConnectPatience);
            await using var second = new TrayIpcClient(pipeName, connectTimeout: ConnectPatience);
            await using var third = new TrayIpcClient(pipeName, connectTimeout: ConnectPatience);

            var responses = await Task.WhenAll(
                first.GetStatusAsync(cts.Token),
                second.GetStatusAsync(cts.Token),
                third.GetStatusAsync(cts.Token));

            Assert.All(responses, r => Assert.True(r.Ok));
            Assert.Equal(3, control.Seen.Count);
        }
        finally
        {
            await server.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task The_client_survives_the_agent_restarting_under_it()
    {
        // The agent is a service and gets patched. A tray that needed restarting each time would
        // train analysts to ignore it.
        var (first, _, pipeName) = Build();
        using var cts = new CancellationTokenSource(Patience);
        await first.StartAsync(cts.Token);

        await using var client = new TrayIpcClient(pipeName, connectTimeout: ConnectPatience);
        Assert.True((await client.GetStatusAsync(cts.Token)).Ok);

        await first.StopAsync(CancellationToken.None);
        first.Dispose();

        var second = new TrayIpcServer(
            new RecordingTrayControl(), Options.Create(new MinaAgentOptions()),
            NullLogger<TrayIpcServer>.Instance)
        {
            PipeName = pipeName,
        };

        await second.StartAsync(cts.Token);
        try
        {
            Assert.True((await client.GetStatusAsync(cts.Token)).Ok);
        }
        finally
        {
            await second.StopAsync(CancellationToken.None);
            second.Dispose();
        }
    }

    [Fact]
    public async Task A_disabled_pipe_is_not_listening()
    {
        var control = new RecordingTrayControl();
        var pipeName = "mina-test-" + Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture);
        using var server = new TrayIpcServer(
            control,
            Options.Create(new MinaAgentOptions { TrayPipe = new TrayPipeOptions { Enabled = false } }),
            NullLogger<TrayIpcServer>.Instance)
        {
            PipeName = pipeName,
        };

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await server.StartAsync(cts.Token);
        try
        {
            // The default (production) connect timeout, deliberately: this is what is under test —
            // that a disabled pipe is detected and reported quickly, not made to wait out a longer
            // CI-friendly allowance the way the other tests in this file do.
            await using var client = new TrayIpcClient(pipeName);

            await Assert.ThrowsAsync<AgentUnavailableException>(() => client.GetStatusAsync(cts.Token));
        }
        finally
        {
            await server.StopAsync(CancellationToken.None);
        }
    }

    [WindowsOnlyFact]
    public async Task A_second_listener_on_the_same_name_is_refused()
    {
        // FirstPipeInstance. On a healthy endpoint the agent starts before any user code, so if the
        // name is already taken either a second agent is running or something has squatted it to sit
        // between the analyst and the agent (THREAT_MODEL B1). The agent refuses to share.
        var (first, _, pipeName) = Build();
        using var cts = new CancellationTokenSource(Patience);
        await first.StartAsync(cts.Token);

        var second = new TrayIpcServer(
            new RecordingTrayControl(), Options.Create(new MinaAgentOptions()),
            NullLogger<TrayIpcServer>.Instance)
        {
            PipeName = pipeName,
        };

        try
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() => second.StartAsync(cts.Token));
        }
        finally
        {
            second.Dispose();
            await first.StopAsync(CancellationToken.None);
            first.Dispose();
        }
    }

    private static async Task<NamedPipeClientStream> ConnectRawAsync(string pipeName, CancellationToken ct)
    {
        var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        await pipe.ConnectAsync(ct);
        return pipe;
    }

    private static async Task<TrayResponse> ReadResponseAsync(Stream stream, CancellationToken ct) =>
        await TrayFraming.ReadAsync(stream, TrayJsonContext.Default.TrayResponse, ct)
        ?? throw new InvalidOperationException("the agent closed without answering");
}

/// <summary>
/// Groups every test that opens a real named pipe into one xUnit collection so they run
/// sequentially against each other. xUnit parallelises across collections by default, and a
/// dozen-plus concurrent pipe servers each waiting on OS-scheduled I/O completion is exactly the
/// kind of load that turns a generous timeout into a flaky one on a 2-core CI runner — confirmed by
/// a real run where even a 20s allowance wasn't enough while these ran alongside each other. Tests
/// that do not touch a pipe (TrayControlServiceTests, TrayPanelTests) are unaffected and keep
/// running in parallel with everything else.
/// </summary>
[CollectionDefinition(TrayIpcCollectionMarker.Name, DisableParallelization = true)]
public sealed class TrayIpcCollectionMarker
{
    public const string Name = "Tray named pipe (sequential)";
}
