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

    /// <summary>
    /// Set to make <see cref="EndAsync"/> fault after closing locally, the way the real
    /// <c>ResearchSessionManager.EndAsync</c> does when telling the control plane fails in a way its
    /// catch filter does not cover. Without this the fake can only ever exercise the happy path,
    /// which is how "End session" came to depend on one.
    /// </summary>
    public Exception? EndThrows { get; set; }

    public Task EndAsync(CancellationToken cancellationToken)
    {
        EndCount++;
        Current = null;
        return EndThrows is null ? Task.CompletedTask : Task.FromException(EndThrows);
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
    // The agent serves several pipe instances at once, so this is called concurrently. A plain
    // List would drop or corrupt entries under that, which showed up as a test that failed only
    // when the whole suite was competing for CPU.
    private readonly Lock _gate = new();
    private readonly List<TrayRequest> _seen = [];
    private string? _lastClientIdentity;

    public IReadOnlyList<TrayRequest> Seen
    {
        get { lock (_gate) { return [.. _seen]; } }
    }

    public string? LastClientIdentity
    {
        get { lock (_gate) { return _lastClientIdentity; } }
    }

    public Func<TrayRequest, TrayResponse>? Respond { get; set; }

    public Task<TrayResponse> ExecuteAsync(
        TrayRequest request, string? clientIdentity, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            _seen.Add(request);
            _lastClientIdentity = clientIdentity;
        }

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

/// <summary>Records every tamper indicator reported, so a test can assert exactly what fired.</summary>
internal sealed class RecordingTamperReporter : ITamperReporter
{
    private readonly Lock _gate = new();
    private readonly List<(string Indicator, Guid? SessionId)> _reported = [];

    public IReadOnlyList<(string Indicator, Guid? SessionId)> Reported
    {
        get { lock (_gate) { return [.. _reported]; } }
    }

    public void Report(string indicator, Guid? sessionId = null)
    {
        lock (_gate)
        {
            _reported.Add((indicator, sessionId));
        }
    }
}
