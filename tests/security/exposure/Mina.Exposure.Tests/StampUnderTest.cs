namespace Mina.Exposure.Tests;

/// <summary>
/// Which deployed stamp these probes run against, read from the environment. Nothing here has a
/// default: a suite that silently pointed at the wrong address would report a clean bill of health
/// for a machine nobody was asking about, and every one of these assertions is a negative — "this
/// is not reachable", "this is not proxied" — which an unreachable host passes trivially.
/// </summary>
/// <remarks>
/// <para>
/// Values come from <c>terraform output</c> in the environment under test:
/// </para>
/// <list type="bullet">
/// <item><c>MINA_STAMP_INGRESS</c> — <c>ingress_public_ip</c>, the address analysts' agents dial.</item>
/// <item><c>MINA_STAMP_SERVER_NAME</c> — SNI to present; defaults to the ingress address.</item>
/// <item><c>MINA_CONTROL_PLANE_URL</c> — the endpoint published from the DMZ (ADR-0006).</item>
/// <item><c>MINA_CA_VAULT_URI</c> — <c>key_vault_uri</c>, for the chained-certificate probe.</item>
/// <item><c>MINA_STAMP_VMSS_RG</c> / <c>MINA_STAMP_VMSS_NAME</c> — for the node-side probes.</item>
/// </list>
/// <para>
/// Run this from outside the platform. Run it from a control-plane host and the reachability
/// assertions describe that host's network position rather than the internet's.
/// </para>
/// </remarks>
internal static class StampUnderTest
{
    public const string IngressVariable = "MINA_STAMP_INGRESS";

    public const string ServerNameVariable = "MINA_STAMP_SERVER_NAME";

    public const string ControlPlaneVariable = "MINA_CONTROL_PLANE_URL";

    public const string VaultVariable = "MINA_CA_VAULT_URI";

    public const string ResourceGroupVariable = "MINA_STAMP_VMSS_RG";

    public const string ScaleSetVariable = "MINA_STAMP_VMSS_NAME";

    /// <summary>The port an analyst's agent connects to. Everything else must be shut.</summary>
    public const int TunnelPort = 443;

    public static string? Ingress => Value(IngressVariable);

    public static string ServerName => Value(ServerNameVariable) ?? Ingress ?? string.Empty;

    public static string? ControlPlaneUrl => Value(ControlPlaneVariable);

    public static string? VaultUri => Value(VaultVariable);

    public static string? ResourceGroup => Value(ResourceGroupVariable);

    public static string? ScaleSet => Value(ScaleSetVariable);

    public static string SkipReason(params string[] variables) =>
        $"Set {string.Join(" and ", variables)} to run this against a deployed stamp.";

    private static string? Value(string name) =>
        Environment.GetEnvironmentVariable(name) is { Length: > 0 } value ? value : null;
}
