namespace Mina.EndpointAgent.Tray;

/// <summary>
/// Tray-side configuration, deployed with the tray via the signed package (M2-5). Small on
/// purpose: everything else the tray needs (region choices, proxy port, session state) comes from
/// the agent over the pipe rather than being configured twice.
/// </summary>
public sealed class TrayOptions
{
    public const string Section = "Mina:Tray";

    /// <summary>The "Mina" app registration's client id (public-client platform).</summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// The tenant the analyst signs into. Scoping the authority to one tenant, rather than
    /// `organizations`, is what keeps the WAM account picker from also offering unrelated
    /// Microsoft accounts signed into the same Windows session.
    /// </summary>
    public string TenantId { get; set; } = string.Empty;

    /// <summary>
    /// The scope requested for the control-plane API. The app exposes no custom API scope — the
    /// control plane validates `aud` as the app's own client id (a v1-style token) rather than an
    /// `api://.../scope` URI — so this is always `{ClientId}/.default`, computed rather than
    /// configured, to keep the two values from ever disagreeing.
    /// </summary>
    public string Scope => $"{ClientId}/.default";

    /// <summary>
    /// The dedicated research-browser profile directory the tray launches into (M2-4). Must equal
    /// the agent's own `Mina:Agent:ResearchBrowser:ProfileDirectory` exactly — that is what
    /// `WindowsPeerAuthorizer` checks a connecting process's actual command line against, so a
    /// mismatch here means the browser this launches is refused by the very controls meant to
    /// admit it (THREAT_MODEL B1).
    /// </summary>
    public string ResearchProfileDirectory { get; set; } = string.Empty;
}
