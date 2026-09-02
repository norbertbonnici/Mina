using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Mina.EgressNode.Sidecar;

namespace Mina.TestSupport;

/// <summary>
/// The sidecar's real admission listener on a socket a test controls, for tests that run a real
/// Envoy. Since M4-11 the committed Envoy config admits no tunnel without it, so every real-Envoy
/// test that expects a tunnel starts one of these and lists the session it is about to use — and a
/// test that wants to prove the node fails closed starts nothing.
/// </summary>
public sealed class SidecarAdmissionHost : IAsyncDisposable
{
    private readonly WebApplication _app;

    private SidecarAdmissionHost(WebApplication app, NodeSessionView view)
    {
        _app = app;
        View = view;
    }

    /// <summary>The view Envoy's checks are answered from. Update it to admit or revoke sessions.</summary>
    public NodeSessionView View { get; }

    public static async Task<SidecarAdmissionHost> StartAsync(string socketPath, TimeProvider? clock = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(socketPath);

        var view = new NodeSessionView();
        var builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.Services.AddSingleton(clock ?? TimeProvider.System);
        builder.Services.AddSingleton(view);
        // No control plane here: a refresh on miss finds nothing new, which is the production
        // outcome for a session that is genuinely not listed.
        builder.Services.AddSingleton<ISessionViewRefresher>(new NoRefresher());
        builder.Services.AddSingleton(Options.Create(new SidecarOptions
        {
            Region = "westeurope",
            ControlPlaneBaseAddress = new Uri("https://control.invalid/"),
            AuthzSocketPath = socketPath,
        }));
        builder.AddSessionAdmissionListener(socketPath);

        var app = builder.Build();
        app.UseSessionAdmission();
        await app.StartAsync().ConfigureAwait(false);
        return new SidecarAdmissionHost(app, view);
    }

    /// <summary>Lists exactly this session, with a current lease, as of now.</summary>
    public void Admit(Guid sessionId) =>
        View.Update([new NodeSession(sessionId, Suppressed: false, DateTimeOffset.UtcNow.AddHours(1))], TimeProvider.System);

    /// <summary>Lists nothing: every session is now unknown to the node.</summary>
    public void RevokeAll() => View.Update([], TimeProvider.System);

    private sealed class NoRefresher : ISessionViewRefresher
    {
        public Task RefreshAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        await _app.StopAsync().ConfigureAwait(false);
        await _app.DisposeAsync().ConfigureAwait(false);
    }
}
