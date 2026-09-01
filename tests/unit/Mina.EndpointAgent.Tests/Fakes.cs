using System.Net;
using System.Net.Http.Json;
using Mina.EndpointAgent.Ipc;
using Mina.EndpointAgent.Session;

namespace Mina.EndpointAgent.Tests;

/// <summary>A session the tray can be told about, without the PKI and tunnel behind a real one.</summary>
internal sealed record FakeSession(
    Guid SessionId, string Region, string Mode, DateTimeOffset LeaseExpiresAt) : IResearchSession;

/// <summary>A session control whose current session the test sets directly.</summary>
internal sealed class FakeSessionControl : ISessionControl
{
    public IResearchSession? Current { get; set; }

    public int EndCount { get; private set; }

    public Task EndAsync(CancellationToken cancellationToken)
    {
        EndCount++;
        Current = null;
        return Task.CompletedTask;
    }
}

/// <summary>
/// Answers control-plane calls from a script, and records what was asked. Stubbing at the HTTP
/// layer rather than behind an interface keeps the real request shapes — routes, bodies, status
/// mapping — under test.
/// </summary>
internal sealed class StubControlPlane : HttpMessageHandler
{
    private readonly List<HttpRequestMessage> _requests = [];

    public IReadOnlyList<HttpRequestMessage> Requests => _requests;

    public IReadOnlyList<string> Regions { get; set; } = ["westeurope", "northeurope"];

    public HttpStatusCode RegionsStatus { get; set; } = HttpStatusCode.OK;

    /// <summary>Set to throw a transport failure instead of answering.</summary>
    public bool Unreachable { get; set; }

    public object? SensitiveResponse { get; set; }

    public HttpStatusCode SensitiveStatus { get; set; } = HttpStatusCode.OK;

    /// <summary>Request bodies as sent, so a test can assert what actually went on the wire.</summary>
    public IList<string> Bodies { get; } = [];

    /// <summary>Paths of every call, in order.</summary>
    public IEnumerable<string> Paths => _requests.Select(r => r.RequestUri?.AbsolutePath ?? string.Empty);

    public int CallsTo(string pathFragment) =>
        Paths.Count(p => p.Contains(pathFragment, StringComparison.Ordinal));

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        _requests.Add(request);
        if (request.Content is not null)
        {
            Bodies.Add(await request.Content.ReadAsStringAsync(cancellationToken));
        }

        if (Unreachable)
        {
            throw new HttpRequestException("the control plane is unreachable in this test");
        }

        var path = request.RequestUri?.AbsolutePath ?? string.Empty;

        if (path.EndsWith("/api/regions", StringComparison.Ordinal))
        {
            return RegionsStatus == HttpStatusCode.OK
                ? new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = JsonContent.Create(new { regions = Regions }),
                }
                : new HttpResponseMessage(RegionsStatus);
        }

        var response = new HttpResponseMessage(SensitiveStatus);
        if (SensitiveStatus == HttpStatusCode.OK && SensitiveResponse is not null)
        {
            response.Content = JsonContent.Create(SensitiveResponse);
        }

        return response;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            foreach (var request in _requests)
            {
                request.Dispose();
            }
        }

        base.Dispose(disposing);
    }
}

/// <summary>A control that records what it was handed and answers with a canned response.</summary>
internal sealed class RecordingTrayControl : ITrayControl
{
    private readonly List<TrayRequest> _seen = [];

    public IReadOnlyList<TrayRequest> Seen => _seen;

    public string? LastClientIdentity { get; private set; }

    public Func<TrayRequest, TrayResponse>? Respond { get; set; }

    public Task<TrayResponse> ExecuteAsync(
        TrayRequest request, string? clientIdentity, CancellationToken cancellationToken)
    {
        _seen.Add(request);
        LastClientIdentity = clientIdentity;

        var response = Respond?.Invoke(request)
                       ?? TrayResponse.Success(new AgentStatusDto { State = ProtectedPathStates.Protected });

        return Task.FromResult(response);
    }
}

/// <summary>A clock the test moves by hand, so throttles and countdowns are exercised deliberately.</summary>
internal sealed class MutableTimeProvider(DateTimeOffset start) : TimeProvider
{
    private DateTimeOffset _now = start;

    public override DateTimeOffset GetUtcNow() => _now;

    public void Advance(TimeSpan by) => _now += by;
}
