using Mina.ControlPlane.Domain.Regions;

namespace Mina.ControlPlane.Domain.Tests;

public class RegionPolicyTests
{
    // The D-08 approved list; only westeurope + northeurope have active stamps in this example.
    private static readonly string[] Approved =
        ["westeurope", "northeurope", "germanywestcentral", "francecentral"];

    private static readonly string[] Active = ["westeurope", "northeurope"];

    private static RegionPolicy Policy() => new(Approved, Active);

    [Fact]
    public void Approved_and_active_region_is_selectable()
    {
        Assert.True(Policy().IsSelectable("westeurope"));
    }

    [Fact]
    public void Approved_but_inactive_region_is_not_selectable()
    {
        var policy = Policy();
        Assert.True(policy.IsApproved("francecentral"));
        Assert.False(policy.IsSelectable("francecentral")); // approved, but no active stamp yet
    }

    [Fact]
    public void Unapproved_region_is_neither_approved_nor_selectable()
    {
        var policy = Policy();
        Assert.False(policy.IsApproved("eastus"));  // outside the EU-only approved list
        Assert.False(policy.IsSelectable("eastus"));
    }

    [Theory]
    [InlineData("WestEurope")]
    [InlineData("WESTEUROPE")]
    public void Region_matching_is_case_insensitive(string region)
    {
        Assert.True(Policy().IsSelectable(region));
    }

    [Fact]
    public void Selectable_regions_lists_only_active_approved_regions()
    {
        Assert.Equal(["northeurope", "westeurope"], Policy().SelectableRegions.OrderBy(r => r));
    }

    [Fact]
    public void Active_region_outside_the_approved_list_is_a_configuration_error()
    {
        Assert.Throws<ArgumentException>(() => new RegionPolicy(["westeurope"], ["westeurope", "eastus"]));
    }
}
