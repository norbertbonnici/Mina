using Mina.EndpointAgent.Ipc;
using Mina.EndpointAgent.Tray;

namespace Mina.EndpointAgent.Tests;

/// <summary>
/// What the analyst is told, for each state the agent can report (FR-006). These are the panel's
/// actual rules — the WPF shell only binds to what this produces.
/// </summary>
public sealed class TrayPanelTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 1, 14, 0, 0, TimeSpan.Zero);

    private static AgentStatusDto Status(string state, Action<AgentStatusDtoBuilder>? configure = null)
    {
        var builder = new AgentStatusDtoBuilder(state);
        configure?.Invoke(builder);
        return builder.Build();
    }

    [Fact]
    public void Protected_session_reads_as_protected_and_names_the_region()
    {
        var panel = TrayPanel.From(Status(ProtectedPathStates.Protected), Now);

        Assert.Equal("Protected", panel.Headline);
        Assert.Equal(TrayTone.Good, panel.Tone);
        Assert.Contains("West Europe", panel.Detail, StringComparison.Ordinal);
        Assert.Null(panel.Alert);
    }

    [Fact]
    public void Protected_session_says_the_rest_of_the_pc_is_unaffected()
    {
        // FR-004 as the analyst experiences it: they must not think Mina has taken over the machine.
        var panel = TrayPanel.From(Status(ProtectedPathStates.Protected), Now);

        Assert.Contains("Everything else on this PC", panel.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void Normal_mode_says_hostnames_are_recorded()
    {
        var panel = TrayPanel.From(Status(ProtectedPathStates.Protected), Now);

        Assert.Equal("Hostnames recorded", panel.LoggingLabel);
        Assert.Equal(TrayTone.Neutral, panel.LoggingTone);
    }

    [Fact]
    public void Sensitive_mode_says_hostnames_are_suppressed()
    {
        var panel = TrayPanel.From(Status(ProtectedPathStates.Protected, b => b.Mode = "Sensitive"), Now);

        Assert.Equal("Hostnames suppressed", panel.LoggingLabel);
        Assert.Equal(TrayTone.Warning, panel.LoggingTone);
    }

    [Fact]
    public void Failed_path_offers_only_retry_and_end()
    {
        // The requirement is the absence: no control on this panel continues browsing over ordinary
        // corporate egress, because there is no such thing to continue with (FR-007).
        var panel = TrayPanel.From(Status(ProtectedPathStates.Failed), Now);

        Assert.Equal(TrayActions.Reconnect | TrayActions.EndSession, panel.Actions);
    }

    [Fact]
    public void Failed_path_tells_the_analyst_nothing_fell_back()
    {
        var panel = TrayPanel.From(Status(ProtectedPathStates.Failed), Now);

        Assert.Equal("Browsing stopped", panel.Headline);
        Assert.Equal(TrayTone.Bad, panel.Tone);
        Assert.NotNull(panel.Alert);
        Assert.Contains("did not fall back", panel.Alert, StringComparison.Ordinal);
    }

    [Fact]
    public void Failed_path_counts_down_to_the_next_attempt()
    {
        var panel = TrayPanel.From(
            Status(ProtectedPathStates.Failed, b =>
            {
                b.Reason = "The control plane cannot be reached from this device.";
                b.ConsecutiveFailures = 2;
                b.NextAttemptAt = Now.AddSeconds(75);
            }),
            Now);

        Assert.Contains("The control plane cannot be reached", panel.Detail, StringComparison.Ordinal);
        Assert.Contains("1:15", panel.Detail, StringComparison.Ordinal);
        Assert.Contains("attempt 3", panel.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void Ended_session_offers_only_starting_another()
    {
        var panel = TrayPanel.From(Status(ProtectedPathStates.Stopped), Now);

        Assert.Equal("Session ended", panel.Headline);
        Assert.Equal(TrayActions.StartSession, panel.Actions);
    }

    [Fact]
    public void Connecting_says_browsing_does_not_work_yet()
    {
        var panel = TrayPanel.From(Status(ProtectedPathStates.Connecting), Now);

        Assert.Equal("Connecting", panel.Headline);
        Assert.Contains("will not work until", panel.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void Live_session_shows_a_short_id_and_the_lease_countdown()
    {
        var id = Guid.Parse("4f2a91c7-0000-0000-0000-000000000000");
        var panel = TrayPanel.From(
            Status(ProtectedPathStates.Protected, b =>
            {
                b.SessionId = id;
                b.LeaseExpiresAt = Now.AddMinutes(4).AddSeconds(12);
            }),
            Now);

        Assert.Equal("4f2a91c7 · lease ends in 4:12", panel.SessionLine);
    }

    [Fact]
    public void A_pending_request_can_be_withdrawn_but_not_started()
    {
        var panel = TrayPanel.From(
            Status(ProtectedPathStates.Protected, b => b.Sensitive = Sensitive("Requested")), Now);

        Assert.True(panel.Actions.HasFlag(TrayActions.CancelSensitive));
        Assert.False(panel.Actions.HasFlag(TrayActions.ActivateSensitive));
        Assert.False(panel.Actions.HasFlag(TrayActions.RequestSensitive));
        Assert.Contains("Waiting for a manager", panel.SensitiveLine, StringComparison.Ordinal);
    }

    [Fact]
    public void An_approved_request_can_be_started_and_names_its_approver()
    {
        var panel = TrayPanel.From(
            Status(ProtectedPathStates.Protected, b => b.Sensitive = Sensitive("Approved") with
            {
                ApproverUpn = "c.spiteri@fiau.example",
            }),
            Now);

        Assert.True(panel.Actions.HasFlag(TrayActions.ActivateSensitive));
        Assert.Contains("c.spiteri@fiau.example", panel.SensitiveLine, StringComparison.Ordinal);
    }

    [Fact]
    public void A_running_suppression_says_expiry_ends_the_session()
    {
        // ADR-0003: the window expiring terminates the session rather than quietly resuming
        // telemetry. The wording has to match, or the analyst plans around the wrong behaviour.
        var panel = TrayPanel.From(
            Status(ProtectedPathStates.Protected, b =>
            {
                b.Mode = "Sensitive";
                b.Sensitive = Sensitive("ActiveSuppressed") with { ExpiresAt = Now.AddMinutes(42) };
            }),
            Now);

        Assert.Contains("then the session ends", panel.SensitiveLine, StringComparison.Ordinal);
        Assert.False(panel.Actions.HasFlag(TrayActions.RequestSensitive));
    }

    [Fact]
    public void Suppression_cannot_be_requested_without_a_live_session()
    {
        var panel = TrayPanel.From(Status(ProtectedPathStates.Failed), Now);

        Assert.False(panel.Actions.HasFlag(TrayActions.RequestSensitive));
    }

    [Fact]
    public void Regions_are_offered_with_readable_names_and_azure_values()
    {
        var panel = TrayPanel.From(
            Status(ProtectedPathStates.Protected, b => b.SelectableRegions = ["westeurope", "francecentral"]),
            Now);

        Assert.True(panel.CanChooseRegion);
        Assert.Collection(
            panel.Regions,
            r => Assert.Equal(new RegionChoice("westeurope", "West Europe"), r),
            r => Assert.Equal(new RegionChoice("francecentral", "France Central"), r));
    }

    [Fact]
    public void An_unknown_region_keeps_its_azure_name_rather_than_disappearing()
    {
        // The control plane owns the list. A region this build has no friendly name for must still
        // be selectable, or a newly approved stamp would be invisible until the tray is updated.
        var panel = TrayPanel.From(
            Status(ProtectedPathStates.Protected, b => b.SelectableRegions = ["atlantis"]), Now);

        Assert.Equal(new RegionChoice("atlantis", "atlantis"), Assert.Single(panel.Regions));
    }

    [Fact]
    public void An_unreachable_agent_still_says_nothing_fell_back()
    {
        var panel = TrayPanel.Unavailable("The Mina agent service is not responding.");

        Assert.Equal(TrayTone.Bad, panel.Tone);
        Assert.Contains("Nothing has moved to your normal internet connection", panel.Alert, StringComparison.Ordinal);
        Assert.Equal(TrayActions.Reconnect, panel.Actions);
    }

    [Fact]
    public void A_refusal_is_carried_through_to_the_panel()
    {
        var panel = TrayPanel.From(
            Status(ProtectedPathStates.Protected), Now, notice: "That region is not available to you.");

        Assert.Equal("That region is not available to you.", panel.Notice);
        Assert.Equal("Protected", panel.Headline);
    }

    private static SensitiveRequestDto Sensitive(string state) => new()
    {
        RequestId = Guid.NewGuid(),
        State = state,
        JustificationReference = "CASE-2026-0417",
        RequestedMinutes = 60,
    };

    internal sealed class AgentStatusDtoBuilder(string state)
    {
        public string Region { get; set; } = "westeurope";

        public string Mode { get; set; } = "Normal";

        public Guid? SessionId { get; set; }

        public DateTimeOffset? LeaseExpiresAt { get; set; }

        public string? Reason { get; set; }

        public int ConsecutiveFailures { get; set; }

        public DateTimeOffset? NextAttemptAt { get; set; }

        public IReadOnlyList<string> SelectableRegions { get; set; } = ["westeurope"];

        public SensitiveRequestDto? Sensitive { get; set; }

        public AgentStatusDto Build() => new()
        {
            State = state,
            Region = Region,
            Mode = Mode,
            SessionId = SessionId,
            LeaseExpiresAt = LeaseExpiresAt,
            Reason = Reason,
            ConsecutiveFailures = ConsecutiveFailures,
            NextAttemptAt = NextAttemptAt,
            SelectableRegions = SelectableRegions,
            Sensitive = Sensitive,
            ObservedAt = Now,
        };
    }
}
