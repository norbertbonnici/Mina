namespace Mina.EndpointAgent.Ipc;

/// <summary>
/// Wire constants shared by the agent's pipe server and the tray client.
/// </summary>
/// <remarks>
/// One UTF-8 JSON object per line, request and response alternating on a duplex named pipe. Line
/// framing rather than a length prefix because <see cref="System.Text.Json"/> never emits a raw
/// newline inside a document, and a text protocol is one an operator can read off a trace when
/// something on the endpoint misbehaves.
/// </remarks>
public static class TrayProtocol
{
    /// <summary>
    /// Pipe the agent listens on. Not configurable by the user: the name is part of the contract
    /// the signed package installs, and a name an attacker could influence is a name they could
    /// point the tray at (THREAT_MODEL B1).
    /// </summary>
    public const string PipeName = "mina-agent";

    /// <summary>
    /// Longest frame either side will read. A tray request is a few hundred bytes; the cap stops a
    /// local process holding the agent's reader open by never sending a newline.
    /// </summary>
    public const int MaxFrameBytes = 64 * 1024;

    /// <summary>How long a connection may sit idle before the agent reclaims the pipe instance.</summary>
    public static readonly TimeSpan IdleTimeout = TimeSpan.FromMinutes(2);

    /// <summary>How long either side waits for one request/response exchange.</summary>
    public static readonly TimeSpan ExchangeTimeout = TimeSpan.FromSeconds(15);

    /// <summary>
    /// How long the tray waits to reach the agent before calling it unavailable. Short on purpose:
    /// connecting to a pipe nobody is listening on otherwise waits indefinitely, and a panel that
    /// froze while the service was down would be worst exactly when the analyst needs to read it.
    /// </summary>
    public static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(2);

    /// <summary>Longest justification reference the agent will forward to the control plane.</summary>
    public const int MaxJustificationReferenceLength = 128;
}

/// <summary>Operations the tray may ask the agent to perform. Anything else is refused.</summary>
public static class TrayOperations
{
    /// <summary>Read the current protected-path state. The only operation with no side effect.</summary>
    public const string Status = "status";

    /// <summary>Choose an egress region. Re-validated against the control plane's list (AC-008).</summary>
    public const string SelectRegion = "select-region";

    /// <summary>Establish the session again now, rather than waiting for the next poll.</summary>
    public const string Reconnect = "reconnect";

    /// <summary>End the session and stop re-establishing it until the analyst asks again.</summary>
    public const string EndSession = "end-session";

    /// <summary>Ask a manager for a time-bound sensitive session.</summary>
    public const string RequestSensitive = "request-sensitive";

    /// <summary>Start an approved suppression window. Refused unless an approver granted it.</summary>
    public const string ActivateSensitive = "activate-sensitive";

    /// <summary>Withdraw a request the analyst raised themselves.</summary>
    public const string CancelSensitive = "cancel-sensitive";

    /// <summary>
    /// Hand the agent a freshly acquired Entra access token (M2-4). The agent runs as SYSTEM in
    /// session 0 and has no access to the interactive user's WAM/PRT, so the tray performs the
    /// broker sign-in and relays the result here rather than the agent acquiring it directly.
    /// </summary>
    public const string SubmitAccessToken = "submit-access-token";
}

/// <summary>
/// Machine-readable refusal codes, paired with the human sentence in
/// <see cref="TrayResponse.Error"/>.
/// </summary>
/// <remarks>
/// As built, the tray shows <see cref="TrayResponse.Error"/> to the analyst verbatim (it becomes
/// <c>TrayViewModel</c>'s notice) and does not branch on these codes. So the sentence the agent
/// writes alongside a code is the one the analyst actually reads, and it has to be true on its own
/// terms — a code that is right paired with a sentence that is wrong is still a wrong answer. These
/// codes are the stable contract for anything that needs to act on a refusal rather than show it.
/// </remarks>
public static class TrayErrorCodes
{
    public const string UnknownOperation = "unknown_operation";
    public const string RegionNotSelectable = "region_not_selectable";
    public const string NoLiveSession = "no_live_session";
    public const string NoSensitiveRequest = "no_sensitive_request";
    public const string NotApproved = "not_approved";
    public const string InvalidRequest = "invalid_request";
    public const string ControlPlaneUnavailable = "control_plane_unavailable";
    public const string ControlPlaneRefused = "control_plane_refused";

    /// <summary>
    /// No access token to attach yet — the tray has not signed in, or the one it relayed has
    /// lapsed. Distinct from <see cref="ControlPlaneUnavailable"/> on purpose: nothing was sent, the
    /// control plane is not implicated, and the analyst's next step is sign-in rather than waiting.
    /// </summary>
    public const string SignInRequired = "sign_in_required";
    public const string AgentFault = "agent_fault";

    /// <summary>
    /// The agent is disposing the component that would have handled this request -- host shutdown,
    /// or the second of two DI registration slots over the same singleton finishing its own dispose
    /// -- and never evaluated it. Distinct from <see cref="AgentFault"/> on purpose: nothing went
    /// wrong with the request itself, so the right next step is retrying once the service is back,
    /// not treating this as a bug report.
    /// </summary>
    public const string AgentShuttingDown = "agent_shutting_down";
}

/// <summary>State of the protected path, as the analyst experiences it (FR-006).</summary>
public static class ProtectedPathStates
{
    /// <summary>A session exists and the research browser has a route out.</summary>
    public const string Protected = "protected";

    /// <summary>Trying to establish or re-establish. Browsing does not work yet.</summary>
    public const string Connecting = "connecting";

    /// <summary>No session and none being sought — the analyst ended it.</summary>
    public const string Stopped = "stopped";

    /// <summary>
    /// The path was lost and could not be rebuilt. This is fail-closed, not degraded: research
    /// browsing does not work, and nothing has fallen back to ordinary corporate egress (FR-007).
    /// </summary>
    public const string Failed = "failed";
}
