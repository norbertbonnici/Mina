using Mina.ControlPlane.Domain.Regions;

namespace Mina.ControlPlane.Domain.Tests;

public class RegionChangeRequestTests
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 11, 9, 0, 0, TimeSpan.Zero);

    private const string RequesterOid = "oid-admin";
    private const string RequesterUpn = "admin@example.org";

    private static RegionChangeRequest NewRequest(
        RegionChangeKind kind = RegionChangeKind.Activate, string region = "northeurope", string justification = "Need EU coverage") =>
        RegionChangeRequest.Create(Guid.NewGuid(), RequesterOid, RequesterUpn, kind, region, justification, T0);

    [Fact]
    public void Create_starts_pending_and_normalises_the_region_name_to_lowercase()
    {
        var request = RegionChangeRequest.Create(
            Guid.NewGuid(), RequesterOid, RequesterUpn, RegionChangeKind.AddApproved, "  NorthEurope  ",
            "  Capacity  ", T0);

        Assert.Equal(RegionChangeRequestStatus.Pending, request.Status);
        Assert.Equal("northeurope", request.RegionName);
        Assert.Equal("Capacity", request.Justification);
        Assert.Equal(RequesterOid, request.RequestedByObjectId);
        Assert.Equal(RequesterUpn, request.RequestedByUpn);
        Assert.Null(request.ResolvedAt);
        Assert.Null(request.ResolutionNote);
    }

    [Fact]
    public void Create_requires_an_actor()
    {
        var ex = Assert.Throws<RegionChangeRuleViolationException>(() =>
            RegionChangeRequest.Create(Guid.NewGuid(), "", "", RegionChangeKind.Activate, "northeurope", "reason", T0));

        Assert.Equal(RegionChangeRule.ActorRequired, ex.Rule);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("North Europe")] // spaces not allowed
    [InlineData("NorthEurope!")] // punctuation not allowed
    public void Create_requires_a_valid_azure_style_region_name(string region)
    {
        var ex = Assert.Throws<RegionChangeRuleViolationException>(() =>
            RegionChangeRequest.Create(Guid.NewGuid(), RequesterOid, RequesterUpn, RegionChangeKind.Activate, region, "reason", T0));

        Assert.Equal(RegionChangeRule.RegionNameRequired, ex.Rule);
    }

    [Fact]
    public void Create_rejects_a_region_name_longer_than_the_column()
    {
        var tooLong = new string('a', RegionChangeRequest.MaxRegionNameLength + 1);
        var ex = Assert.Throws<RegionChangeRuleViolationException>(() =>
            RegionChangeRequest.Create(Guid.NewGuid(), RequesterOid, RequesterUpn, RegionChangeKind.Activate, tooLong, "reason", T0));

        Assert.Equal(RegionChangeRule.RegionNameRequired, ex.Rule);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Create_requires_a_justification(string justification)
    {
        var ex = Assert.Throws<RegionChangeRuleViolationException>(() =>
            RegionChangeRequest.Create(Guid.NewGuid(), RequesterOid, RequesterUpn, RegionChangeKind.Activate, "northeurope", justification, T0));

        Assert.Equal(RegionChangeRule.JustificationRequired, ex.Rule);
    }

    [Fact]
    public void Create_rejects_a_justification_longer_than_the_column()
    {
        var tooLong = new string('a', RegionChangeRequest.MaxJustificationLength + 1);
        var ex = Assert.Throws<RegionChangeRuleViolationException>(() =>
            RegionChangeRequest.Create(Guid.NewGuid(), RequesterOid, RequesterUpn, RegionChangeKind.Activate, "northeurope", tooLong, T0));

        Assert.Equal(RegionChangeRule.JustificationRequired, ex.Rule);
    }

    [Fact]
    public void MarkApplied_transitions_to_applied_and_records_who_and_when()
    {
        var request = NewRequest();
        var resolvedAt = T0.AddHours(2);

        request.MarkApplied("oid-resolver", "resolver@example.org", resolvedAt, "deployed via script run #42");

        Assert.Equal(RegionChangeRequestStatus.Applied, request.Status);
        Assert.Equal("oid-resolver", request.ResolvedByObjectId);
        Assert.Equal("resolver@example.org", request.ResolvedByUpn);
        Assert.Equal(resolvedAt, request.ResolvedAt);
        Assert.Equal("deployed via script run #42", request.ResolutionNote);
    }

    [Fact]
    public void MarkApplied_accepts_no_note_at_all()
    {
        var request = NewRequest();
        request.MarkApplied("oid-resolver", "resolver@example.org", T0.AddHours(1), note: null);

        Assert.Equal(RegionChangeRequestStatus.Applied, request.Status);
        Assert.Null(request.ResolutionNote);
    }

    [Fact]
    public void The_same_person_who_requested_may_also_resolve_it()
    {
        // Deliberately different from SensitiveSessionRequest: there is no second-party-authorization
        // property to protect here, since this workflow never itself authorizes anything -- the
        // reviewed deploy script does. The requester going and running that script themselves, then
        // marking their own request applied, is an expected shape, not a self-approval loophole.
        var request = NewRequest();
        request.MarkApplied(RequesterOid, RequesterUpn, T0.AddHours(1), "I ran it myself");

        Assert.Equal(RegionChangeRequestStatus.Applied, request.Status);
        Assert.Equal(RequesterOid, request.ResolvedByObjectId);
    }

    [Fact]
    public void Dismiss_requires_a_reason()
    {
        var request = NewRequest();
        var ex = Assert.Throws<RegionChangeRuleViolationException>(() =>
            request.Dismiss("oid-resolver", "resolver@example.org", T0.AddHours(1), ""));

        Assert.Equal(RegionChangeRule.ResolutionNoteRequired, ex.Rule);
        Assert.Equal(RegionChangeRequestStatus.Pending, request.Status); // unchanged
    }

    [Fact]
    public void Dismiss_transitions_to_dismissed_and_records_the_reason()
    {
        var request = NewRequest();
        request.Dismiss("oid-resolver", "resolver@example.org", T0.AddHours(1), "superseded by another request");

        Assert.Equal(RegionChangeRequestStatus.Dismissed, request.Status);
        Assert.Equal("superseded by another request", request.ResolutionNote);
    }

    [Fact]
    public void A_resolved_request_cannot_be_resolved_again()
    {
        var request = NewRequest();
        request.MarkApplied("oid-a", "a@example.org", T0.AddHours(1), null);

        var ex = Assert.Throws<RegionChangeRuleViolationException>(() =>
            request.MarkApplied("oid-b", "b@example.org", T0.AddHours(2), null));
        Assert.Equal(RegionChangeRule.InvalidTransition, ex.Rule);

        var ex2 = Assert.Throws<RegionChangeRuleViolationException>(() =>
            request.Dismiss("oid-b", "b@example.org", T0.AddHours(2), "reason"));
        Assert.Equal(RegionChangeRule.InvalidTransition, ex2.Rule);
    }
}
