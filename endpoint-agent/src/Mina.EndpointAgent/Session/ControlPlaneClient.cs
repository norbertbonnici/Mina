using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;

namespace Mina.EndpointAgent.Session;

/// <summary>A session grant as returned by the control plane.</summary>
public sealed record SessionGrantResponse(
    Guid SessionId,
    string CertificatePem,
    string CertificateSerialNumber,
    string Region,
    string EgressHost,
    int EgressPort,
    string EgressServerName,
    DateTimeOffset LeaseExpiresAt,
    string Mode);

/// <summary>A sensitive-session request as the control plane reports it back to the requester.</summary>
public sealed record SensitiveRequestResponse(
    Guid RequestId,
    Guid SessionId,
    string RequesterUpn,
    string JustificationReference,
    int RequestedMinutes,
    DateTimeOffset RequestedAt,
    string State,
    string? ApproverUpn,
    DateTimeOffset? ApprovedAt,
    DateTimeOffset? ExpiresAt,
    DateTimeOffset? ActivatedAt);

/// <summary>The regions this analyst may select, as decided by the control plane (AC-008).</summary>
public sealed record SelectableRegionsResponse(IReadOnlyList<string> Regions);

/// <summary>Raised when the control plane refuses or cannot service a session request.</summary>
public sealed class ControlPlaneException : Exception
{
    public ControlPlaneException()
    {
    }

    public ControlPlaneException(string message)
        : base(message)
    {
    }

    public ControlPlaneException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    public ControlPlaneException(string message, HttpStatusCode statusCode)
        : base(message)
    {
        StatusCode = statusCode;
    }

    public HttpStatusCode? StatusCode { get; }
}

/// <summary>
/// Talks to the control-plane session API. Every call carries a freshly acquired Entra token, and
/// every issuance/renewal sends a CSR whose private key stays on the endpoint.
/// </summary>
public sealed class ControlPlaneClient(HttpClient httpClient, IAccessTokenProvider tokenProvider)
{
    private readonly HttpClient _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));

    private readonly IAccessTokenProvider _tokenProvider =
        tokenProvider ?? throw new ArgumentNullException(nameof(tokenProvider));

    public async Task<SessionGrantResponse> IssueAsync(string region, byte[] csr, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "api/sessions")
        {
            Content = JsonContent.Create(new { region, csrPem = ToPem(csr) }),
        };

        return await SendForGrantAsync(request, cancellationToken).ConfigureAwait(false);
    }

    public async Task<SessionGrantResponse> RenewAsync(Guid sessionId, byte[] csr, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, $"api/sessions/{sessionId}/renew")
        {
            Content = JsonContent.Create(new { csrPem = ToPem(csr) }),
        };

        return await SendForGrantAsync(request, cancellationToken).ConfigureAwait(false);
    }

    public async Task EndAsync(Guid sessionId, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Delete, $"api/sessions/{sessionId}");
        using var response = await SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode && response.StatusCode != HttpStatusCode.NotFound)
        {
            throw new ControlPlaneException(
                $"Ending session {sessionId} failed with {(int)response.StatusCode}.", response.StatusCode);
        }
    }

    /// <summary>
    /// The regions the control plane offers this analyst. The agent caches the answer so the tray
    /// can show a list, but the control plane re-validates the choice on every issuance — the cache
    /// is a convenience, never the authority.
    /// </summary>
    public async Task<IReadOnlyList<string>> GetSelectableRegionsAsync(CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "api/regions");
        using var response = await SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw new ControlPlaneException(
                $"The control plane returned {(int)response.StatusCode} for the region list.",
                response.StatusCode);
        }

        var payload = await response.Content
            .ReadFromJsonAsync<SelectableRegionsResponse>(cancellationToken).ConfigureAwait(false);

        return payload?.Regions ?? [];
    }

    /// <summary>Raises a suppression request against a session this analyst owns (FR-009).</summary>
    public Task<SensitiveRequestResponse> RequestSensitiveAsync(
        Guid sessionId, string justificationReference, int minutes, CancellationToken cancellationToken)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, $"api/sessions/{sessionId}/sensitive")
        {
            Content = JsonContent.Create(new { justificationReference, requestedMinutes = minutes }),
        };

        return SendForSensitiveAsync(request, cancellationToken);
    }

    /// <summary>Reads the current state of a request, so the tray can follow the decision.</summary>
    public Task<SensitiveRequestResponse> GetSensitiveAsync(Guid requestId, CancellationToken cancellationToken) =>
        SendForSensitiveAsync(
            new HttpRequestMessage(HttpMethod.Get, $"api/sensitive-requests/{requestId}"), cancellationToken);

    /// <summary>
    /// Starts an approved suppression window. The control plane checks that an approver — someone
    /// other than the requester — granted it; the agent cannot confer suppression on itself.
    /// </summary>
    public Task<SensitiveRequestResponse> ActivateSensitiveAsync(
        Guid requestId, CancellationToken cancellationToken) =>
        SendForSensitiveAsync(
            new HttpRequestMessage(HttpMethod.Post, $"api/sensitive-requests/{requestId}/activate"),
            cancellationToken);

    /// <summary>Withdraws a request the analyst raised themselves.</summary>
    public Task<SensitiveRequestResponse> CancelSensitiveAsync(
        Guid requestId, CancellationToken cancellationToken) =>
        SendForSensitiveAsync(
            new HttpRequestMessage(HttpMethod.Delete, $"api/sensitive-requests/{requestId}"), cancellationToken);

    /// <summary>
    /// Reports a tamper indicator the agent's own self-monitoring detected (ARCHITECTURE §3.1 point
    /// 5), recorded as `client_tamper_suspected` (EVENT_SCHEMAS §3). Callers wanting best-effort,
    /// fire-and-forget semantics should go through <see cref="TamperReporter"/> instead — this
    /// method itself still surfaces failures rather than swallowing them.
    /// </summary>
    public async Task ReportTamperAsync(string indicator, Guid? sessionId, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "api/agent/tamper-events")
        {
            Content = JsonContent.Create(new { indicator, sessionId }),
        };

        using var response = await SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw new ControlPlaneException(
                $"The control plane answered {(int)response.StatusCode} to a tamper report.",
                response.StatusCode);
        }
    }

    private async Task<SensitiveRequestResponse> SendForSensitiveAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        using (request)
        {
            using var response = await SendAsync(request, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                throw new ControlPlaneException(
                    $"The control plane answered {(int)response.StatusCode}.", response.StatusCode);
            }

            return await response.Content
                       .ReadFromJsonAsync<SensitiveRequestResponse>(cancellationToken).ConfigureAwait(false)
                   ?? throw new ControlPlaneException("The control plane returned an empty request record.");
        }
    }

    private async Task<SessionGrantResponse> SendForGrantAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        using var response = await SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            if (response.StatusCode == HttpStatusCode.Unauthorized &&
                TryParseClaimsChallenge(response, out var claimsChallenge))
            {
                // The token that was just used cannot satisfy this on its own — recorded here so
                // whatever acquires tokens for this provider (the tray, over the pipe, in
                // production) learns what to re-acquire with, then surfaces as an ordinary refusal
                // so the caller's existing retry/backoff handles it exactly like any other 401.
                if (_tokenProvider is IClaimsChallengeReceiver receiver)
                {
                    receiver.RecordClaimsChallenge(claimsChallenge);
                }

                throw new ControlPlaneException(
                    "The control plane requires a fresher sign-in (Conditional Access step-up).",
                    response.StatusCode);
            }

            throw new ControlPlaneException(
                $"The control plane refused the session request with {(int)response.StatusCode}.",
                response.StatusCode);
        }

        return await response.Content.ReadFromJsonAsync<SessionGrantResponse>(cancellationToken).ConfigureAwait(false)
            ?? throw new ControlPlaneException("The control plane returned an empty session grant.");
    }

    /// <summary>
    /// Extracts the claims-challenge JSON from a <c>WWW-Authenticate: Bearer
    /// error="insufficient_claims", claims="&lt;base64&gt;"</c> header, matching exactly what
    /// <c>ClaimsChallengeResult</c> on the control plane emits. Returns false for any 401 that is
    /// not this specific challenge, so an ordinary "your sign-in is no longer accepted" 401 is not
    /// mistaken for one MSAL's <c>.WithClaims(...)</c> can actually resolve.
    /// </summary>
    private static bool TryParseClaimsChallenge(HttpResponseMessage response, out string claimsChallenge)
    {
        claimsChallenge = string.Empty;

        var challenge = response.Headers.WwwAuthenticate
            .FirstOrDefault(h => string.Equals(h.Scheme, "Bearer", StringComparison.OrdinalIgnoreCase)
                && h.Parameter?.Contains("error=\"insufficient_claims\"", StringComparison.Ordinal) == true);
        if (challenge?.Parameter is not { } parameter)
        {
            return false;
        }

        var marker = "claims=\"";
        var start = parameter.IndexOf(marker, StringComparison.Ordinal);
        if (start < 0)
        {
            return false;
        }

        start += marker.Length;
        var end = parameter.IndexOf('"', start);
        if (end < 0)
        {
            return false;
        }

        try
        {
            claimsChallenge = Encoding.UTF8.GetString(Convert.FromBase64String(parameter[start..end]));
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var token = await _tokenProvider.GetAccessTokenAsync(cancellationToken).ConfigureAwait(false);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }

    private static string ToPem(byte[] csr) => PemEncoding.WriteString("CERTIFICATE REQUEST", csr);
}
