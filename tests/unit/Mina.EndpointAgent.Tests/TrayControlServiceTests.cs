using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Mina.EndpointAgent.Configuration;
using Mina.EndpointAgent.Ipc;
using Mina.EndpointAgent.Session;

namespace Mina.EndpointAgent.Tests;

/// <summary>
/// The agent's side of the tray boundary. Everything here is a check the tray cannot skip by
/// sending a different message, which is the point of ARCHITECTURE §3.1's "all privileged
/// operations validated server-side in the agent".
/// </summary>
public sealed class TrayControlServiceTests : IDisposable
{
    private static readonly DateTimeOffset Start = new(2026, 9, 1, 14, 0, 0, TimeSpan.Zero);

    private readonly StubControlPlane _controlPlane = new();
    private readonly HttpClient _http;
    private readonly FakeSessionControl _sessions = new();
    private readonly MutableTimeProvider _clock = new(Start);
    private readonly AgentRuntimeState _state;
    private readonly TrayFedAccessTokenProvider _tokenSink;
    private readonly TrayControlService _service;

    public TrayControlServiceTests()
    {
        _http = new HttpClient(_controlPlane) { BaseAddress = new Uri("https://control.mina.example/") };
        var options = Options.Create(new MinaAgentOptions
        {
            ControlPlaneBaseAddress = new Uri("https://control.mina.example/"),
            Region = "westeurope",
            MaxSensitiveRequestMinutes = 240,
        });

        _state = new AgentRuntimeState(options);
        _tokenSink = new TrayFedAccessTokenProvider(_clock);
        _service = new TrayControlService(
            _sessions,
            new ControlPlaneClient(_http, new ConfiguredAccessTokenProvider("test-token")),
            _state,
            _tokenSink,
            options,
            _clock,
            NullLogger<TrayControlService>.Instance);
    }

    private Task<TrayResponse> ExecuteAsync(TrayRequest request) =>
        _service.ExecuteAsync(request, "CORP\\j.camilleri", CancellationToken.None);

    private Task<TrayResponse> ExecuteAsync(string op) => ExecuteAsync(new TrayRequest { Op = op });

    private void GiveLiveSession(string mode = "Normal") =>
        _sessions.Current = new FakeSession(Guid.NewGuid(), "westeurope", mode, Start.AddMinutes(30));

    [Fact]
    public async Task An_operation_the_agent_does_not_know_is_refused()
    {
        var response = await ExecuteAsync("drop-all-rules");

        Assert.False(response.Ok);
        Assert.Equal(TrayErrorCodes.UnknownOperation, response.Code);
    }

    [Fact]
    public async Task Status_fetches_the_region_list_from_the_control_plane()
    {
        var response = await ExecuteAsync(TrayOperations.Status);

        Assert.True(response.Ok);
        Assert.Equal(["westeurope", "northeurope"], response.Status!.SelectableRegions);
    }

    [Fact]
    public async Task Status_still_answers_before_the_tray_has_ever_signed_in()
    {
        // Found live 2026-09-05: this shared fixture's ControlPlaneClient is backed by a token
        // provider that always succeeds, so it could never exercise what happens before the tray's
        // very first SubmitAccessToken -- which crashed the real agent's first-ever status query
        // with an unhandled NoAccessTokenAvailableException, uncaught by either RefreshRegionsAsync
        // or the top-level catch. Wiring ControlPlaneClient to the same TrayFedAccessTokenProvider
        // TrayControlService itself uses -- exactly how Program.cs wires production -- reproduces
        // that gap; only a targeted fix, not a coincidence of this fixture's setup, should pass it.
        var freshTokenSink = new TrayFedAccessTokenProvider(_clock);
        var service = new TrayControlService(
            _sessions,
            new ControlPlaneClient(_http, freshTokenSink),
            _state,
            freshTokenSink,
            Options.Create(new MinaAgentOptions
            {
                ControlPlaneBaseAddress = new Uri("https://control.mina.example/"),
                Region = "westeurope",
                MaxSensitiveRequestMinutes = 240,
            }),
            _clock,
            NullLogger<TrayControlService>.Instance);

        var response = await service.ExecuteAsync(
            new TrayRequest { Op = TrayOperations.Status }, "CORP\\j.camilleri", CancellationToken.None);

        Assert.True(response.Ok);
        Assert.Empty(response.Status!.SelectableRegions);
    }

    [Fact]
    public async Task An_operation_needing_a_token_asks_for_sign_in_rather_than_blaming_the_control_plane()
    {
        // NoAccessTokenAvailableException is thrown before anything is sent, so reporting it as
        // "The control plane cannot be reached. Research browsing stays closed until it can." put
        // two false statements in front of the analyst and hid the only thing they can act on.
        // Status cannot show this -- it degrades to a stale panel by design -- so it takes an
        // operation that really does reach the control plane to see what the analyst is told.
        var freshTokenSink = new TrayFedAccessTokenProvider(_clock);
        using var service = new TrayControlService(
            _sessions,
            new ControlPlaneClient(_http, freshTokenSink),
            _state,
            freshTokenSink,
            Options.Create(new MinaAgentOptions
            {
                ControlPlaneBaseAddress = new Uri("https://control.mina.example/"),
                Region = "westeurope",
                MaxSensitiveRequestMinutes = 240,
            }),
            _clock,
            NullLogger<TrayControlService>.Instance);

        GiveLiveSession();

        var response = await service.ExecuteAsync(
            new TrayRequest
            {
                Op = TrayOperations.RequestSensitive,
                JustificationReference = "CASE-2026-0417",
                Minutes = 60,
            },
            "CORP\\j.camilleri",
            CancellationToken.None);

        Assert.False(response.Ok);
        Assert.Equal(TrayErrorCodes.SignInRequired, response.Code);

        // The substance of the fix, not just its wording: nothing was sent, so nothing about the
        // control plane's reachability was ever learned and none of it belongs in the answer.
        Assert.Empty(_controlPlane.Requests);
        Assert.DoesNotContain("control plane", response.Error!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Status_still_answers_while_a_tracked_sensitive_request_cannot_be_refreshed()
    {
        // The third of the three catch filters widened for M2-4, and the last one no test reached.
        // RefreshSensitiveAsync returns early unless a sensitive request is tracked AND unsettled,
        // so every other test in this file skips its control-plane call entirely: the fixture's
        // service holds a token that always works, and the two token-less tests leave
        // SensitiveRequest null. Both preconditions have to be arranged together to get inside the
        // try block at all, which is why this gap survived.
        //
        // The state it reproduces is ordinary: the analyst raised a request, it is still Requested,
        // and WAM stops acquiring silently (machine slept, PRT needs interaction) so the held token
        // falls inside TrayFedAccessTokenProvider's expiry margin. The next status poll must still
        // render the panel from what it already knows.
        var freshTokenSink = new TrayFedAccessTokenProvider(_clock);
        using var service = new TrayControlService(
            _sessions,
            new ControlPlaneClient(_http, freshTokenSink),
            _state,
            freshTokenSink,
            Options.Create(new MinaAgentOptions
            {
                ControlPlaneBaseAddress = new Uri("https://control.mina.example/"),
                Region = "westeurope",
                MaxSensitiveRequestMinutes = 240,
            }),
            _clock,
            NullLogger<TrayControlService>.Instance);

        var tracked = new SensitiveRequestDto
        {
            RequestId = Guid.NewGuid(),
            State = "Requested",
            JustificationReference = "CASE-2026-0417",
            RequestedMinutes = 60,
        };
        _state.SetSensitiveRequest(tracked);

        // Guard the precondition rather than assume it: a settled state would take the early return
        // and this test would pass with the catch filter removed, proving nothing.
        Assert.Equal("Requested", _state.SensitiveRequest!.State);

        var response = await service.ExecuteAsync(
            new TrayRequest { Op = TrayOperations.Status }, "CORP\\j.camilleri", CancellationToken.None);

        Assert.True(response.Ok);
        Assert.Equal(tracked.RequestId, response.Status!.Sensitive!.RequestId);
        Assert.Equal("Requested", response.Status.Sensitive.State);
    }

    [Fact]
    public async Task Status_still_answers_when_the_control_plane_is_down()
    {
        // The panel is most needed exactly when the control plane is unreachable. A status call
        // that failed then would leave the analyst with a blank window and no explanation.
        _controlPlane.Unreachable = true;

        var response = await ExecuteAsync(TrayOperations.Status);

        Assert.True(response.Ok);
        Assert.Empty(response.Status!.SelectableRegions);
    }

    [Fact]
    public async Task The_region_list_is_not_refetched_on_every_poll()
    {
        await ExecuteAsync(TrayOperations.Status);
        await ExecuteAsync(TrayOperations.Status);
        await ExecuteAsync(TrayOperations.Status);

        Assert.Equal(1, _controlPlane.CallsTo("/api/regions"));
    }

    [Fact]
    public async Task The_region_list_is_refetched_once_the_cache_lapses()
    {
        await ExecuteAsync(TrayOperations.Status);
        _clock.Advance(TimeSpan.FromMinutes(6));
        await ExecuteAsync(TrayOperations.Status);

        Assert.Equal(2, _controlPlane.CallsTo("/api/regions"));
    }

    [Fact]
    public async Task A_region_the_control_plane_did_not_offer_is_refused()
    {
        // AC-008. The control plane refuses the issuance too; this is the agent declining to carry
        // the request at all.
        await ExecuteAsync(TrayOperations.Status);

        var response = await ExecuteAsync(
            new TrayRequest { Op = TrayOperations.SelectRegion, Region = "eastus" });

        Assert.False(response.Ok);
        Assert.Equal(TrayErrorCodes.RegionNotSelectable, response.Code);
        Assert.Equal("westeurope", _state.Region);
    }

    [Fact]
    public async Task An_offered_region_is_taken_and_ends_the_current_session()
    {
        await ExecuteAsync(TrayOperations.Status);
        GiveLiveSession();

        var response = await ExecuteAsync(
            new TrayRequest { Op = TrayOperations.SelectRegion, Region = "northeurope" });

        Assert.True(response.Ok);
        Assert.Equal("northeurope", _state.Region);
        Assert.Equal(1, _sessions.EndCount);
        Assert.False(_state.Suspended);
    }

    [Fact]
    public async Task Region_matching_ignores_case_but_stores_the_control_planes_spelling()
    {
        await ExecuteAsync(TrayOperations.Status);

        await ExecuteAsync(new TrayRequest { Op = TrayOperations.SelectRegion, Region = "NorthEurope" });

        Assert.Equal("northeurope", _state.Region);
    }

    [Fact]
    public async Task Ending_a_session_stops_the_agent_rebuilding_it()
    {
        GiveLiveSession();

        var response = await ExecuteAsync(TrayOperations.EndSession);

        Assert.True(response.Ok);
        Assert.True(_state.Suspended);
        Assert.Equal(1, _sessions.EndCount);
        Assert.Equal(ProtectedPathStates.Stopped, response.Status!.State);
    }

    [Fact]
    public async Task Ending_a_session_stops_the_agent_rebuilding_it_even_if_the_end_call_fails()
    {
        // The session is closed locally before the control plane is told, so by the time anything can
        // throw the path is already down -- but nothing keeps it down except state.Suspended, which
        // used to be set only on the happy path. An analyst whose token had lapsed therefore got a
        // failure notice while the worker was still free to re-establish on its next tick: "End
        // session" meant "end it for a few seconds".
        GiveLiveSession();
        _sessions.EndThrows = new NoAccessTokenAvailableException("no token yet");

        var response = await ExecuteAsync(TrayOperations.EndSession);

        Assert.False(response.Ok);
        Assert.True(_state.Suspended);
        Assert.Equal(1, _sessions.EndCount);
    }

    [Fact]
    public async Task Choosing_a_region_while_stopped_records_it_without_starting_a_session()
    {
        // The analyst ended their session and is deciding where the next one goes. Starting one for
        // them would take the decision away.
        await ExecuteAsync(TrayOperations.Status);
        await ExecuteAsync(TrayOperations.EndSession);

        var response = await ExecuteAsync(
            new TrayRequest { Op = TrayOperations.SelectRegion, Region = "northeurope" });

        Assert.True(response.Ok);
        Assert.Equal("northeurope", _state.Region);
        Assert.True(_state.Suspended);
        Assert.Equal(ProtectedPathStates.Stopped, response.Status!.State);
    }

    [Fact]
    public async Task Reconnecting_lifts_the_suspension()
    {
        await ExecuteAsync(TrayOperations.EndSession);

        await ExecuteAsync(TrayOperations.Reconnect);

        Assert.False(_state.Suspended);
    }

    [Fact]
    public async Task Suppression_cannot_be_requested_without_a_live_session()
    {
        var response = await Request("CASE-1", 60);

        Assert.False(response.Ok);
        Assert.Equal(TrayErrorCodes.NoLiveSession, response.Code);
        Assert.Equal(0, _controlPlane.CallsTo("/sensitive"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task Suppression_needs_a_justification_reference(string reference)
    {
        GiveLiveSession();

        var response = await Request(reference, 60);

        Assert.False(response.Ok);
        Assert.Equal(TrayErrorCodes.InvalidRequest, response.Code);
        Assert.Equal(0, _controlPlane.CallsTo("/sensitive"));
    }

    [Fact]
    public async Task A_justification_reference_may_not_carry_control_characters()
    {
        // It is written to the audit trail and read back by an approver. A local process must not
        // be able to shape how that record renders.
        GiveLiveSession();

        var response = await Request("CASE-1\r\nApproved: yes", 60);

        Assert.False(response.Ok);
        Assert.Equal(TrayErrorCodes.InvalidRequest, response.Code);
    }

    [Fact]
    public async Task An_over_long_justification_reference_is_refused_here_not_at_the_control_plane()
    {
        GiveLiveSession();

        var response = await Request(new string('x', TrayProtocol.MaxJustificationReferenceLength + 1), 60);

        Assert.False(response.Ok);
        Assert.Equal(TrayErrorCodes.InvalidRequest, response.Code);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-5)]
    [InlineData(241)]
    public async Task A_window_outside_policy_is_refused(int minutes)
    {
        GiveLiveSession();

        var response = await Request("CASE-1", minutes);

        Assert.False(response.Ok);
        Assert.Equal(TrayErrorCodes.InvalidRequest, response.Code);
        Assert.Equal(0, _controlPlane.CallsTo("/sensitive"));
    }

    [Fact]
    public async Task A_valid_request_reaches_the_control_plane_and_is_tracked()
    {
        GiveLiveSession();
        var requestId = Guid.NewGuid();
        _controlPlane.SensitiveResponse = SensitivePayload(requestId, "Requested");

        var response = await Request("  CASE-2026-0417  ", 60);

        Assert.True(response.Ok);
        Assert.Equal(requestId, response.Status!.Sensitive!.RequestId);
        Assert.Equal("Requested", response.Status.Sensitive.State);

        // Trimmed before it is sent, so the audit record does not carry the analyst's stray spaces.
        Assert.Contains("CASE-2026-0417", Assert.Single(_controlPlane.Bodies), StringComparison.Ordinal);
        Assert.DoesNotContain("  CASE", Assert.Single(_controlPlane.Bodies), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Suppression_cannot_be_started_before_a_manager_approves_it()
    {
        // AC-010. The control plane would refuse this too; refusing here keeps the tray from
        // presenting activation as though approval were a formality.
        GiveLiveSession();
        _controlPlane.SensitiveResponse = SensitivePayload(Guid.NewGuid(), "Requested");
        await Request("CASE-1", 60);

        var response = await ExecuteAsync(TrayOperations.ActivateSensitive);

        Assert.False(response.Ok);
        Assert.Equal(TrayErrorCodes.NotApproved, response.Code);
        Assert.Equal(0, _controlPlane.CallsTo("/activate"));
    }

    [Fact]
    public async Task An_approved_request_can_be_started()
    {
        GiveLiveSession();
        var requestId = Guid.NewGuid();
        _controlPlane.SensitiveResponse = SensitivePayload(requestId, "Approved");
        await Request("CASE-1", 60);

        _controlPlane.SensitiveResponse = SensitivePayload(requestId, "ActiveSuppressed");
        var response = await ExecuteAsync(TrayOperations.ActivateSensitive);

        Assert.True(response.Ok);
        Assert.Equal(1, _controlPlane.CallsTo("/activate"));
        Assert.Equal("ActiveSuppressed", response.Status!.Sensitive!.State);
    }

    [Fact]
    public async Task An_activated_request_makes_the_reported_mode_sensitive_before_the_next_renewal()
    {
        // The session grant carries the mode stamped at issuance, so it lags activation. Both
        // readings come from the control plane; the newer one wins.
        GiveLiveSession(mode: "Normal");
        var requestId = Guid.NewGuid();
        _controlPlane.SensitiveResponse = SensitivePayload(requestId, "Approved");
        await Request("CASE-1", 60);

        _controlPlane.SensitiveResponse = SensitivePayload(requestId, "ActiveSuppressed");
        var response = await ExecuteAsync(TrayOperations.ActivateSensitive);

        Assert.Equal("Sensitive", response.Status!.Mode);
    }

    [Fact]
    public async Task There_is_nothing_to_start_when_no_request_exists()
    {
        GiveLiveSession();

        var response = await ExecuteAsync(TrayOperations.ActivateSensitive);

        Assert.False(response.Ok);
        Assert.Equal(TrayErrorCodes.NoSensitiveRequest, response.Code);
    }

    [Fact]
    public async Task A_control_plane_refusal_is_reported_as_a_refusal_not_a_fault()
    {
        GiveLiveSession();
        _controlPlane.SensitiveStatus = HttpStatusCode.Forbidden;

        var response = await Request("CASE-1", 60);

        Assert.False(response.Ok);
        Assert.Equal(TrayErrorCodes.ControlPlaneRefused, response.Code);
        Assert.NotNull(response.Status);
    }

    [Fact]
    public async Task An_unreachable_control_plane_is_distinguished_from_a_refusal()
    {
        GiveLiveSession();
        _controlPlane.Unreachable = true;

        var response = await Request("CASE-1", 60);

        Assert.False(response.Ok);
        Assert.Equal(TrayErrorCodes.ControlPlaneUnavailable, response.Code);
    }

    [Fact]
    public async Task A_refusal_still_carries_the_current_status()
    {
        GiveLiveSession();

        var response = await Request("", 60);

        Assert.False(response.Ok);
        Assert.NotNull(response.Status);
        Assert.Equal("westeurope", response.Status.Region);
    }

    [Fact]
    public async Task A_submitted_token_is_accepted_and_wakes_the_worker()
    {
        var response = await ExecuteAsync(new TrayRequest
        {
            Op = TrayOperations.SubmitAccessToken,
            AccessToken = "a-real-token",
            AccessTokenExpiresOn = Start.AddMinutes(60),
        });

        Assert.True(response.Ok);
        Assert.Equal("a-real-token", await _tokenSink.GetAccessTokenAsync(CancellationToken.None));
    }

    [Fact]
    public async Task An_empty_token_is_refused()
    {
        var response = await ExecuteAsync(new TrayRequest
        {
            Op = TrayOperations.SubmitAccessToken,
            AccessToken = "   ",
            AccessTokenExpiresOn = Start.AddMinutes(60),
        });

        Assert.False(response.Ok);
        Assert.Equal(TrayErrorCodes.InvalidRequest, response.Code);
    }

    [Fact]
    public async Task An_already_expired_token_is_refused()
    {
        var response = await ExecuteAsync(new TrayRequest
        {
            Op = TrayOperations.SubmitAccessToken,
            AccessToken = "a-real-token",
            AccessTokenExpiresOn = Start.AddMinutes(-1),
        });

        Assert.False(response.Ok);
        Assert.Equal(TrayErrorCodes.InvalidRequest, response.Code);
    }

    [Fact]
    public async Task A_token_with_no_expiry_is_refused()
    {
        var response = await ExecuteAsync(new TrayRequest
        {
            Op = TrayOperations.SubmitAccessToken,
            AccessToken = "a-real-token",
        });

        Assert.False(response.Ok);
        Assert.Equal(TrayErrorCodes.InvalidRequest, response.Code);
    }

    [Fact]
    public async Task Status_reports_an_outstanding_claims_challenge()
    {
        _tokenSink.RecordClaimsChallenge("""{"access_token":{"acrs":{"essential":true,"value":"c1"}}}""");

        var response = await ExecuteAsync(TrayOperations.Status);

        Assert.Equal(
            """{"access_token":{"acrs":{"essential":true,"value":"c1"}}}""", response.Status!.RequiredClaims);
    }

    [Fact]
    public async Task Submitting_a_token_clears_a_pending_claims_challenge_optimistically()
    {
        _tokenSink.RecordClaimsChallenge("""{"access_token":{"acrs":{"essential":true,"value":"c1"}}}""");

        var response = await ExecuteAsync(new TrayRequest
        {
            Op = TrayOperations.SubmitAccessToken,
            AccessToken = "a-fresher-token",
            AccessTokenExpiresOn = Start.AddMinutes(60),
        });

        Assert.Null(response.Status!.RequiredClaims);
    }

    /// <summary>
    /// <c>Program.cs</c> registers this type under two singleton slots (<c>TrayControlService</c>
    /// directly, and <c>ITrayControl</c> via a factory resolving the same instance), and the
    /// built-in <c>ServiceProvider</c> disposes each registration independently at host shutdown --
    /// the same shape that crashed <c>ResearchSessionManager</c> live on 2026-09-05. These four
    /// prove the analogous guard on <see cref="TrayControlService"/> holds, even though no live
    /// crash was observed here: <see cref="TrayIpcServer"/>'s own catch-all already turns an
    /// escaping exception into an <c>agent_fault</c> response, so this component's own contract,
    /// not the caller's safety net, is what these exercise.
    /// </summary>
    [Fact]
    public void Calling_Dispose_a_second_time_does_not_throw()
    {
        _service.Dispose();

        var exception = Record.Exception(() => _service.Dispose());

        Assert.Null(exception);
    }

    [Fact]
    public async Task ExecuteAsync_called_after_disposal_does_not_throw()
    {
        _service.Dispose();

        var exception = await Record.ExceptionAsync(() => ExecuteAsync(TrayOperations.Status));

        Assert.Null(exception);
    }

    [Fact]
    public async Task ExecuteAsync_after_disposal_is_refused_as_shutting_down_not_a_fault()
    {
        _service.Dispose();

        var response = await ExecuteAsync(TrayOperations.Status);

        Assert.False(response.Ok);
        Assert.Equal(TrayErrorCodes.AgentShuttingDown, response.Code);
    }

    [Fact]
    public async Task ExecuteAsync_racing_disposal_from_a_different_caller_does_not_throw()
    {
        // Closer to the live DI shape: the two registration slots' Dispose calls and an in-flight
        // request are not strictly ordered relative to each other.
        var request = ExecuteAsync(TrayOperations.Status);
        var disposeException = Record.Exception(() => _service.Dispose());
        var requestException = await Record.ExceptionAsync(() => request);

        Assert.Null(disposeException);
        Assert.Null(requestException);
    }

    private Task<TrayResponse> Request(string reference, int minutes) =>
        ExecuteAsync(new TrayRequest
        {
            Op = TrayOperations.RequestSensitive,
            JustificationReference = reference,
            Minutes = minutes,
        });

    private static object SensitivePayload(Guid requestId, string state) => new
    {
        requestId,
        sessionId = Guid.NewGuid(),
        requesterUpn = "j.camilleri@example.org",
        justificationReference = "CASE-2026-0417",
        requestedMinutes = 60,
        requestedAt = Start,
        state,
        approverUpn = state is "Approved" or "ActiveSuppressed" ? "c.spiteri@example.org" : null,
        approvedAt = (DateTimeOffset?)(state is "Approved" or "ActiveSuppressed" ? Start : null),
        expiresAt = (DateTimeOffset?)(state == "ActiveSuppressed" ? Start.AddMinutes(60) : null),
        activatedAt = (DateTimeOffset?)(state == "ActiveSuppressed" ? Start : null),
    };

    public void Dispose()
    {
        _service.Dispose();
        _state.Dispose();
        _http.Dispose();
        _controlPlane.Dispose();
    }
}
