namespace Mina.EgressNode.Sidecar;

/// <summary>Configuration for the egress-node sidecar.</summary>
public sealed class SidecarOptions
{
    public const string Section = "Mina:Sidecar";

    /// <summary>Control-plane base address.</summary>
    public Uri? ControlPlaneBaseAddress { get; set; }

    /// <summary>The region this node serves; sessions for other regions are not its business.</summary>
    public string Region { get; set; } = string.Empty;

    /// <summary>Envoy's access log, one `mina.hostname.v1` JSON record per line.</summary>
    public string AccessLogPath { get; set; } = "/var/log/mina/envoy-access.log";

    /// <summary>How often the suppression allowlist is refreshed from the control plane.</summary>
    public TimeSpan AllowlistRefreshInterval { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>How often queued telemetry is shipped.</summary>
    public TimeSpan ShipInterval { get; set; } = TimeSpan.FromSeconds(10);
}
