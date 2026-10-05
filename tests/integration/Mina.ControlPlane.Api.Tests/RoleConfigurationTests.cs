using System.Net;
using Microsoft.Extensions.Options;

namespace Mina.ControlPlane.Api.Tests;

/// <summary>
/// The role names every policy is built from are configuration (M2-6, config drift). Two things
/// have to hold. Renaming them must actually move the gate — a policy that silently kept its
/// default would let the documented default role through a tenant that had deliberately renamed
/// it. And the one role that is named twice (<c>Mina:Session:AnalystRole</c> and
/// <c>Mina:SensitiveSession:AnalystRole</c>) must not be allowed to drift apart, since nothing at
/// runtime would report that it had (SECURITY_REVIEW_2026-09-01 #32).
/// </summary>
public sealed class RoleConfigurationTests
{
    private static readonly Dictionary<string, string?> Renamed = new()
    {
        ["Mina:Session:AnalystRole"] = "Custom.Analyst",
        ["Mina:SensitiveSession:AnalystRole"] = "Custom.Analyst",
        ["Mina:SensitiveSession:ApproverRole"] = "Custom.Approver",
        ["Mina:Node:Role"] = "Custom.Node",
        ["Mina:Audit:AdminRole"] = "Custom.Admin",
        ["Mina:Telemetry:ViewerRole"] = "Custom.Viewer",
    };

    private static HttpClient Client(MinaApiFactory factory, string oid, string roles)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Test-Oid", oid);
        client.DefaultRequestHeaders.Add("X-Test-Upn", $"{oid}@example.org");
        client.DefaultRequestHeaders.Add("X-Test-Device", "device-1");
        client.DefaultRequestHeaders.Add("X-Test-Roles", roles);
        return client;
    }

    /// <summary>One read-only route per policy, the default role it would admit, and the renamed one.</summary>
    public static IEnumerable<object[]> PoliciesAndRoutes()
    {
        yield return ["/api/regions", "Mina.Analyst", "Custom.Analyst"];
        yield return ["/api/sensitive-requests/pending", "Mina.Approver", "Custom.Approver"];
        // The per-region grant keeps its fixed prefix (NodeRegionGrant.RolePrefix); only the node
        // role itself is renamed, so the renamed caller still carries the grant.
        yield return ["/api/nodes/westeurope/sessions", "Mina.Node,Mina.Node.westeurope", "Custom.Node,Mina.Node.westeurope"];
        yield return ["/api/audit/recent", "Mina.Admin", "Custom.Admin"];
        yield return ["/api/browsing-data/analysts", "Mina.TelemetryViewer", "Custom.Viewer"];
    }

    [Theory]
    [MemberData(nameof(PoliciesAndRoutes))]
    public async Task Renaming_a_role_moves_its_gate_so_the_default_name_no_longer_passes(
        string path, string defaultRoles, string renamedRoles)
    {
        await using var factory = new MinaApiFactory(Renamed);

        using var withDefault = await Client(factory, "oid-default", defaultRoles)
            .GetAsync(new Uri(path, UriKind.Relative));
        Assert.Equal(HttpStatusCode.Forbidden, withDefault.StatusCode);

        using var withRenamed = await Client(factory, "oid-renamed", renamedRoles)
            .GetAsync(new Uri(path, UriKind.Relative));
        Assert.Equal(HttpStatusCode.OK, withRenamed.StatusCode);
    }

    [Fact]
    public async Task A_host_whose_two_analyst_role_settings_disagree_refuses_to_start()
    {
        // Only one of the pair renamed. Before the validator this host started and ran: sessions
        // were issued to Custom.Analyst while suppression requests were still gated on Mina.Analyst,
        // so no analyst could request one and nothing said why.
        await using var factory = new MinaApiFactory(new Dictionary<string, string?>
        {
            ["Mina:Session:AnalystRole"] = "Custom.Analyst",
        });

        var exception = Record.Exception(() => factory.CreateClient());

        Assert.NotNull(exception);
        var validation = Unwrap(exception).OfType<OptionsValidationException>().FirstOrDefault();
        Assert.NotNull(validation);
        Assert.Contains("Mina:SensitiveSession:AnalystRole", validation.Message, StringComparison.Ordinal);
        Assert.Contains("Mina:Session:AnalystRole", validation.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_host_whose_two_analyst_role_settings_agree_on_a_renamed_value_starts()
    {
        // The positive control for the test above: renaming both together is the supported shape.
        await using var factory = new MinaApiFactory(new Dictionary<string, string?>
        {
            ["Mina:Session:AnalystRole"] = "Custom.Analyst",
            ["Mina:SensitiveSession:AnalystRole"] = "Custom.Analyst",
        });

        using var response = await Client(factory, "oid-both", "Custom.Analyst")
            .GetAsync(new Uri("/api/regions", UriKind.Relative));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    private static IEnumerable<Exception> Unwrap(Exception exception)
    {
        var queue = new Queue<Exception>([exception]);
        while (queue.Count > 0)
        {
            var current = queue.Dequeue();
            yield return current;
            if (current is AggregateException aggregate)
            {
                foreach (var inner in aggregate.InnerExceptions)
                {
                    queue.Enqueue(inner);
                }
            }
            else if (current.InnerException is not null)
            {
                queue.Enqueue(current.InnerException);
            }
        }
    }
}
