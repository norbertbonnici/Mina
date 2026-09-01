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

    /// <summary>Wait before the first retry after the protected path fails.</summary>
    public TimeSpan RetryInitialDelay { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Longest wait between retries. The backoff doubles up to this; it never gives up, because a
    /// path that stays closed is the safe state and the analyst can see exactly why.
    /// </summary>
    public TimeSpan RetryMaxDelay { get; set; } = TimeSpan.FromMinutes(2);

    /// <summary>How long the agent reuses the control plane's region list before refetching.</summary>
    public TimeSpan RegionCacheLifetime { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// How often the agent re-reads an undecided sensitive request. Fast enough that an approval
    /// shows up while the analyst is still looking at the panel; slow enough that a tray polling
    /// once a second does not become a control-plane call once a second.
    /// </summary>
    public TimeSpan SensitivePollInterval { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Longest suppression window the tray may ask for. The control plane holds the real policy
    /// ceiling; this only stops the agent forwarding an obviously out-of-range request.
    /// </summary>
    public int MaxSensitiveRequestMinutes { get; set; } = 240;

    /// <summary>Settings for the pipe the per-user tray connects on.</summary>
    public TrayPipeOptions TrayPipe { get; set; } = new();
}

/// <summary>The local IPC surface the tray uses (ARCHITECTURE §3.1).</summary>
public sealed class TrayPipeOptions
{
    /// <summary>
    /// Whether to listen at all. A deployment with no tray — a kiosk, or a test host — should not
    /// carry a local endpoint nothing consumes.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Concurrent pipe instances. Small on purpose: one interactive user needs one, and a handful
    /// of spares absorbs reconnects without giving a local process many sockets to hold open.
    /// </summary>
    public int Instances { get; set; } = 4;
}
