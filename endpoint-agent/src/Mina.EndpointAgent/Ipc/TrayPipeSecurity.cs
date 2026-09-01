using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Mina.EndpointAgent.Ipc;

/// <summary>
/// The pipe's access control (ARCHITECTURE §3.1: "SDDL restricted — SYSTEM + interactive user
/// read/write").
/// </summary>
[SupportedOSPlatform("windows")]
public static class TrayPipeSecurity
{
    /// <summary>
    /// Builds the DACL. Three deliberate choices:
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>INTERACTIVE, not a named account.</b> The well-known INTERACTIVE group is exactly "code
    /// running in an interactive logon session", which is who the tray is. Resolving the logged-on
    /// user instead would mean re-ACLing the pipe on every logon and getting it wrong at the
    /// switch-user boundary.
    /// </para>
    /// <para>
    /// <b>Read and write only — no CreateNewInstance.</b> Without that right the interactive user
    /// cannot add an instance of this pipe name, so a process running as the analyst cannot join the
    /// listener set and answer the tray in the agent's place.
    /// </para>
    /// <para>
    /// <b>No entry for Administrators.</b> An administrator can take ownership regardless, so this
    /// is not a boundary against them; leaving them out keeps the DACL an honest statement of who
    /// the pipe is for. Network access is impossible by construction — a named pipe reached over
    /// SMB authenticates as NETWORK, which appears nowhere below.
    /// </para>
    /// </remarks>
    public static PipeSecurity Create()
    {
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, domainSid: null);
        var interactive = new SecurityIdentifier(WellKnownSidType.InteractiveSid, domainSid: null);

        var security = new PipeSecurity();
        security.SetOwner(system);
        security.AddAccessRule(new PipeAccessRule(system, PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            interactive,
            PipeAccessRights.Read | PipeAccessRights.Write | PipeAccessRights.Synchronize,
            AccessControlType.Allow));

        return security;
    }
}
