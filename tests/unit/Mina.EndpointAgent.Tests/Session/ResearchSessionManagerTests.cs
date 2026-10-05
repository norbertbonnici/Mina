using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Mina.EndpointAgent.Configuration;
using Mina.EndpointAgent.Session;

namespace Mina.EndpointAgent.Tests.Session;

/// <summary>
/// <see cref="ResearchSessionManager"/>'s shutdown-time disposal. <c>Program.cs</c> registers this
/// type under two singleton slots -- <c>ResearchSessionManager</c> directly, and <c>ISessionControl</c>
/// via a factory that resolves the same instance -- and the built-in <c>ServiceProvider</c> tracks
/// disposables per registration, not per object identity, so both slots call <c>DisposeAsync</c> at
/// host shutdown. <c>ProtectedPathWorker</c>'s own shutdown <c>finally</c> separately calls
/// <c>EndAsync</c> directly, by design (see that method's own remarks). Found live 2026-09-05
/// (<c>Stop-Service -Force</c>): the second caller into either path reached the mutex after the
/// first had already disposed it, throwing <see cref="ObjectDisposedException"/> unhandled and
/// crashing the whole endpoint-agent process. These tests reproduce the shape of that race directly
/// against the mutex/disposal machinery, without needing a full PKI/session-establishment harness --
/// every case here deliberately never establishes a session, so it exercises exactly the disposal
/// path that crashed, nothing more.
/// </summary>
public sealed class ResearchSessionManagerTests
{
    private static ResearchSessionManager NewManager()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=Mina Test CA", key, HashAlgorithmName.SHA256);
        using var ca = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));

        var httpClient = new HttpClient(new NeverCalledHandler())
        {
            BaseAddress = new Uri("https://control.mina.example/"),
        };
        var controlPlane = new ControlPlaneClient(httpClient, new ConfiguredAccessTokenProvider("test-token"));
        var options = Options.Create(new MinaAgentOptions
        {
            Region = "westeurope",
            EgressCaCertificatePem = ca.ExportCertificatePem(),
        });

        return new ResearchSessionManager(
            controlPlane, options, TimeProvider.System, NullLogger<ResearchSessionManager>.Instance);
    }

    [Fact]
    public async Task Calling_DisposeAsync_a_second_time_does_not_throw()
    {
        var sessions = NewManager();

        await sessions.DisposeAsync();
        var second = await Record.ExceptionAsync(async () => await sessions.DisposeAsync());

        Assert.Null(second);
    }

    [Fact]
    public async Task Concurrent_DisposeAsync_calls_do_not_throw()
    {
        // The actual shape of the live bug: two independent callers -- the DI container's two
        // singleton slots -- invoking DisposeAsync at effectively the same moment, not one cleanly
        // after the other.
        var sessions = NewManager();

        var first = sessions.DisposeAsync().AsTask();
        var second = sessions.DisposeAsync().AsTask();
        var exception = await Record.ExceptionAsync(() => Task.WhenAll(first, second));

        Assert.Null(exception);
    }

    [Fact]
    public async Task EndAsync_called_after_disposal_does_not_throw()
    {
        // ProtectedPathWorker's shutdown finally calls EndAsync directly, independently of
        // DisposeAsync -- if it runs after disposal has already completed (a slow or forceful stop
        // giving the host reason to proceed without waiting for that task to finish), this must not
        // be the second way to crash the process on the same exception type.
        var sessions = NewManager();
        await sessions.DisposeAsync();

        var exception = await Record.ExceptionAsync(() => sessions.EndAsync(CancellationToken.None));

        Assert.Null(exception);
    }

    [Fact]
    public async Task EndAsync_racing_disposal_from_a_different_caller_does_not_throw()
    {
        // Closer still to the live interleaving: EndAsync (standing in for ProtectedPathWorker's
        // call) and DisposeAsync started at the same time, rather than strictly one after the other.
        var sessions = NewManager();

        var endAsync = sessions.EndAsync(CancellationToken.None);
        var disposeAsync = sessions.DisposeAsync().AsTask();
        var exception = await Record.ExceptionAsync(() => Task.WhenAll(endAsync, disposeAsync));

        Assert.Null(exception);
    }

    /// <summary>Confirms the constructor's cert-parsing guard doesn't reject its own test fixture.</summary>
    [Fact]
    public async Task The_test_fixture_itself_constructs_successfully()
    {
        await using var sessions = NewManager();
        Assert.Null(sessions.Current);
    }

    private sealed class NeverCalledHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) =>
            throw new InvalidOperationException(
                "No test in this file establishes a session, so the control plane must never be called.");
    }
}
