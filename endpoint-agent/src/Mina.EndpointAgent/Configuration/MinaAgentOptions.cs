namespace Mina.EndpointAgent.Configuration;

/// <summary>Endpoint-agent configuration, deployed with the signed package via Intune.</summary>
public sealed class MinaAgentOptions
{
    public const string Section = "Mina:Agent";

    /// <summary>Base address of the control-plane API.</summary>
    public Uri? ControlPlaneBaseAddress { get; set; }

    /// <summary>Egress region the analyst has selected. The control plane re-validates it (AC-008).</summary>
    public string Region { get; set; } = string.Empty;

    /// <summary>
    /// PEM of Mina's internal CA, used to validate the egress server certificate. It is delivered
    /// with the agent package (out of band) rather than fetched from the control plane, so the
    /// tunnel's trust anchor does not depend on the same channel it authenticates.
    /// </summary>
    public string EgressCaCertificatePem { get; set; } = string.Empty;

    /// <summary>
    /// Loopback port for the CONNECT proxy. 0 picks a free port, which is the better default: the
    /// agent launches the research browser and passes it the actual port, so nothing needs to
    /// predict it.
    /// </summary>
    public int LoopbackPort { get; set; }

    /// <summary>Renew once less than this remains of the lease.</summary>
    public TimeSpan RenewMargin { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>How often the agent checks session health and renewal.</summary>
    public TimeSpan PollInterval { get; set; } = TimeSpan.FromSeconds(30);
}
