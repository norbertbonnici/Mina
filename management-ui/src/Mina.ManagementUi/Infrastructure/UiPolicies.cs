namespace Mina.ManagementUi.Infrastructure;

/// <summary>Authorization policy names used by the management screens.</summary>
public static class UiPolicies
{
    public const string Approver = "MinaApprover";

    public const string Admin = "MinaAdmin";

    /// <summary>
    /// Browsing-data review (M3-8). Deliberately its own policy, not <see cref="Approver"/>:
    /// approving a sensitive-session request and reading an analyst's browsing history are
    /// different privileges, and THREAT_MODEL N10's purpose-limitation mitigation is weaker if
    /// every approver is automatically also a telemetry viewer.
    /// </summary>
    public const string TelemetryViewer = "MinaTelemetryViewer";
}
