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

    /// <summary>
    /// How often the session view is refreshed from the control plane. Bounds how long a revoked
    /// session can still open a new tunnel, and how long a new session waits before its first
    /// tunnel is admitted without a refresh on miss.
    /// </summary>
    public TimeSpan AllowlistRefreshInterval { get; set; } = TimeSpan.FromSeconds(15);

    /// <summary>How often queued telemetry is shipped.</summary>
    public TimeSpan ShipInterval { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>
    /// The Unix socket on which the sidecar answers Envoy's admission checks (M4-11). A path, never a
    /// TCP endpoint: on a forward proxy, loopback is reachable through the proxy itself, and a pipe
    /// is not addressable through CONNECT at all.
    /// </summary>
    public string AuthzSocketPath { get; set; } = "/run/mina-sidecar/authz.sock";

    /// <summary>
    /// How old the session view may be before the node stops admitting anyone. Past this the node
    /// cannot know which of the sessions it lists have been revoked, so it fails closed — a control
    /// plane unreachable for longer than this stops research browsing on the node (CLAUDE.md
    /// property 2). Five minutes is twenty missed refreshes: long enough that a proxy restart or a
    /// rate-limit response on the published endpoint does not take a node out, short enough that
    /// a partition in which the control plane can still revoke leaves revocation unseen for at
    /// most this long. Recorded as decision D-19.
    /// </summary>
    public TimeSpan AdmissionMaxViewAge { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// How long an admission check waits for a refresh on miss before answering from the view it
    /// has. Envoy's own check timeout is the outer bound; this stays inside it.
    /// </summary>
    public TimeSpan AdmissionRefreshOnMissTimeout { get; set; } = TimeSpan.FromSeconds(2);

    public IEnumerable<string> Validate()
    {
        if (string.IsNullOrWhiteSpace(Region))
        {
            yield return $"{Section}:Region is required.";
        }

        if (ControlPlaneBaseAddress is null)
        {
            yield return $"{Section}:ControlPlaneBaseAddress is required.";
        }

        if (string.IsNullOrWhiteSpace(AuthzSocketPath) || !Path.IsPathRooted(AuthzSocketPath))
        {
            yield return $"{Section}:AuthzSocketPath must be an absolute filesystem path.";
        }

        if (AllowlistRefreshInterval < TimeSpan.FromSeconds(1))
        {
            yield return $"{Section}:AllowlistRefreshInterval must be at least one second.";
        }

        // A view age below one refresh interval would refuse sessions between refreshes even with
        // a perfectly healthy control plane; the floor is two, so one slow refresh is tolerated.
        if (AdmissionMaxViewAge < AllowlistRefreshInterval + AllowlistRefreshInterval)
        {
            yield return $"{Section}:AdmissionMaxViewAge must be at least twice {Section}:AllowlistRefreshInterval.";
        }

        // Past the lease TTL the certificate has expired anyway; a larger value would only be
        // claiming a tolerance the platform cannot deliver.
        if (AdmissionMaxViewAge > TimeSpan.FromMinutes(60))
        {
            yield return $"{Section}:AdmissionMaxViewAge must not exceed the session lease (60 minutes).";
        }

        if (AdmissionRefreshOnMissTimeout <= TimeSpan.Zero || AdmissionRefreshOnMissTimeout > TimeSpan.FromSeconds(10))
        {
            yield return $"{Section}:AdmissionRefreshOnMissTimeout must be between 1ms and 10s.";
        }
    }
}
