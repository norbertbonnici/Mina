using Microsoft.Extensions.Options;
using Mina.ControlPlane.Application.Audit;
using Mina.ControlPlane.Application.Regions;
using Mina.ControlPlane.Application.Sessions;
using Mina.ControlPlane.Domain.Audit;
using Mina.ControlPlane.Domain.Regions;
using Mina.ControlPlane.Persistence;

namespace Mina.ControlPlane.Application.Tests;

/// <summary>
/// The region change request workflow (ADR-0008 Option C). What matters most here is what the
/// workflow deliberately does *not* do — it never touches Mina:Regions:Approved/Active itself — and
/// that every transition reaches the audit chain, including policy_changed finally getting a real
/// producer on "applied".
/// </summary>
public sealed class RegionChangeRequestServiceTests
{
    private static readonly SessionPrincipal Admin = new(
        "oid-admin", "admin@example.org", "device-1", new HashSet<string> { "Mina.Admin" }, DeviceBound: true);

    private static readonly SessionPrincipal NonAdmin = new(
        "oid-analyst", "analyst@example.org", "device-2", new HashSet<string> { "Mina.Analyst" }, DeviceBound: true);

    private static (RegionChangeRequestService Service, InMemoryRegionChangeRequestRepository Repo, InMemoryAuditEventStore Audit) Build()
    {
        var repo = new InMemoryRegionChangeRequestRepository();
        var auditStore = new InMemoryAuditEventStore();
        var writer = new AuditWriter(auditStore, Options.Create(new AuditOptions { Environment = "test" }), TimeProvider.System);
        var service = new RegionChangeRequestService(repo, writer, TimeProvider.System, Options.Create(new RegionChangeRequestOptions()));
        return (service, repo, auditStore);
    }

    [Fact]
    public async Task An_admin_can_submit_a_request_and_it_lands_pending()
    {
        var (service, _, _) = Build();

        var view = await service.RequestAsync(Admin, RegionChangeKind.Activate, "northeurope", "capacity need", default);

        Assert.Equal(RegionChangeRequestStatus.Pending, view.Status);
        Assert.Equal("northeurope", view.RegionName);
        Assert.Equal(Admin.UserPrincipalName, view.RequestedByUpn);
    }

    [Fact]
    public async Task A_non_admin_cannot_submit_a_request()
    {
        var (service, _, _) = Build();

        await Assert.ThrowsAsync<RegionChangeRequestAuthorizationException>(() =>
            service.RequestAsync(NonAdmin, RegionChangeKind.Activate, "northeurope", "reason", default));
    }

    [Fact]
    public async Task Requesting_writes_region_change_requested_to_the_audit_chain()
    {
        var (service, _, audit) = Build();

        await service.RequestAsync(Admin, RegionChangeKind.AddApproved, "francesouth", "expansion", default);

        var events = await audit.ReadRecentAsync(50, default);
        var e = Assert.Single(events, e => e.EventType == "region_change_requested");
        Assert.Equal(Admin.UserPrincipalName, e.UserPrincipalName);
        Assert.Equal(AuditSeverity.Notice, e.Severity);
        Assert.Contains("francesouth", e.Data, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Marking_applied_transitions_the_request_and_writes_policy_changed_at_high_severity()
    {
        var (service, _, audit) = Build();
        var requested = await service.RequestAsync(Admin, RegionChangeKind.Activate, "northeurope", "capacity", default);

        var applied = await service.MarkAppliedAsync(Admin, requested.Id, "deployed via script run", default);

        Assert.Equal(RegionChangeRequestStatus.Applied, applied.Status);
        Assert.Equal("deployed via script run", applied.ResolutionNote);

        var events = await audit.ReadRecentAsync(50, default);
        var e = Assert.Single(events, e => e.EventType == "policy_changed");
        Assert.Equal(AuditSeverity.High, e.Severity);
        Assert.Contains("Mina:Regions:Active", e.Data, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Applying_an_AddApproved_request_names_the_approved_list_not_the_active_one()
    {
        var (service, _, audit) = Build();
        var requested = await service.RequestAsync(Admin, RegionChangeKind.AddApproved, "francesouth", "expansion", default);

        await service.MarkAppliedAsync(Admin, requested.Id, null, default);

        var events = await audit.ReadRecentAsync(50, default);
        var e = Assert.Single(events, e => e.EventType == "policy_changed");
        Assert.Contains("Mina:Regions:Approved", e.Data, StringComparison.Ordinal);
        Assert.DoesNotContain("Mina:Regions:Active", e.Data, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Dismissing_requires_a_reason_and_writes_region_change_dismissed()
    {
        var (service, _, audit) = Build();
        var requested = await service.RequestAsync(Admin, RegionChangeKind.Deactivate, "spaincentral", "no longer needed", default);

        var dismissed = await service.DismissAsync(Admin, requested.Id, "kept active after all", default);

        Assert.Equal(RegionChangeRequestStatus.Dismissed, dismissed.Status);
        var events = await audit.ReadRecentAsync(50, default);
        var e = Assert.Single(events, e => e.EventType == "region_change_dismissed");
        Assert.Equal(AuditSeverity.Notice, e.Severity);
    }

    [Fact]
    public async Task Resolving_an_unknown_request_throws_not_found()
    {
        var (service, _, _) = Build();

        await Assert.ThrowsAsync<RegionChangeRequestNotFoundException>(() =>
            service.MarkAppliedAsync(Admin, Guid.NewGuid(), null, default));
    }

    [Fact]
    public async Task ListPending_only_ever_returns_pending_requests()
    {
        var (service, _, _) = Build();
        var toApply = await service.RequestAsync(Admin, RegionChangeKind.Activate, "northeurope", "reason a", default);
        await service.RequestAsync(Admin, RegionChangeKind.Deactivate, "westeurope", "reason b", default);
        await service.MarkAppliedAsync(Admin, toApply.Id, null, default);

        var pending = await service.ListPendingAsync(Admin, default);

        var view = Assert.Single(pending);
        Assert.Equal("westeurope", view.RegionName);
    }

    [Fact]
    public async Task ListRecentlyResolved_only_ever_returns_resolved_requests()
    {
        var (service, _, _) = Build();
        var toApply = await service.RequestAsync(Admin, RegionChangeKind.Activate, "northeurope", "reason a", default);
        await service.RequestAsync(Admin, RegionChangeKind.Deactivate, "westeurope", "reason b", default);
        await service.MarkAppliedAsync(Admin, toApply.Id, null, default);

        var resolved = await service.ListRecentlyResolvedAsync(Admin, default);

        var view = Assert.Single(resolved);
        Assert.Equal("northeurope", view.RegionName);
        Assert.Equal(RegionChangeRequestStatus.Applied, view.Status);
    }
}
