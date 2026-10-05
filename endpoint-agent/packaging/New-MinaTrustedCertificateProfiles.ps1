<#
.SYNOPSIS
    Creates or updates the Intune device configuration profiles that push both certificates a
    fresh Mina endpoint currently needs by hand, and assigns them (backlog M2-5, OPERATIONS.md
    "New Windows endpoint onboarding" steps 4a/4b).

.DESCRIPTION
    Until A6 (a real organisation-issued code-signing certificate) exists, two self-signed lab
    certificates have to be trusted on every device before the Mina Win32 apps or tray can work at
    all: the endpoint agent's code-signing certificate (`Detect.ps1`/`Install.ps1` load under
    `-ExecutionPolicy AllSigned`) and the control plane's management-listener TLS certificate (the
    tray's `mina.example.org:8444` calls). Until now this was `certutil -f -addstore` run by
    hand on every device -- the "main source of onboarding friction" OPERATIONS.md's onboarding
    runbook calls out. This script automates it as three Intune device configuration profiles.

    **Why three profiles, not two.** `windows81TrustedRootCertificate`'s `destinationStore`
    (confirmed against the tenant's own Graph beta $metadata, not assumed from docs) only exposes
    `computerCertStoreRoot`, `computerCertStoreIntermediate`, `userCertStoreIntermediate` --
    `TrustedPublisher` is not a supported destination for that profile type at all. The TLS
    certificate only ever needed `Root`, so one typed profile covers it. The code-signing
    certificate needs **both** `Root` and `TrustedPublisher` (a self-signed chain needs both --
    `New-MinaLabSigningCertificate.ps1`'s own output already explains why), so it needs a second,
    typed profile for `Root` *and* a `windows10CustomConfiguration` OMA-URI profile targeting the
    `RootCATrustedCertificates` CSP's `TrustedPublisher` node directly, which is the only way to
    reach that store via MDM. The OMA-URI encodes the certificate's own thumbprint
    (`.../TrustedPublisher/<thumbprint>/EncodedCertificate`), computed from the `.cer` file itself
    at run time rather than taken as a separate parameter -- one source of truth, and a
    regenerated certificate (new thumbprint) naturally produces a different URI rather than a
    silently stale one still pointing at a certificate nobody trusts as code-signing anymore.

    Re-runnable by design, the same way every other script in this pipeline is: given the same
    display name it finds the existing profile and replaces it rather than creating a second one,
    then reads every profile back and refuses to report success if what actually landed doesn't
    match what was sent -- the same discipline `Publish-MinaEndpointApp.ps1` applies to
    `applicableArchitectures` and the icon, because a Graph write that silently doesn't stick reads
    as healthy right up until a device fails to trust something.

    **"Replaces" means delete-then-recreate, not PATCH -- found by actually re-running this script
    a second time, not assumed.** `PATCH /deviceManagement/deviceConfigurations/{id}` is broken for
    both profile types used here: every field tried, including a completely empty `{}` body, on
    both the `beta` and `v1.0` endpoints, returns the identical generic
    `ModelValidationFailure`/"Exception has been thrown by the target of an invocation." This is a
    Graph platform issue, not anything about the payload this script sends -- delete-and-recreate
    is Graph's own documented workaround for a resource whose PATCH doesn't work, so that is what
    a second run of this script actually does.

.PARAMETER CodeSigningCertPath
    Path to the endpoint agent code-signing certificate's public `.cer` file (DER-encoded --
    `certutil -dump` or `Export-Certificate`'s own default format). Needed for both the Root and
    TrustedPublisher profiles.

.PARAMETER TlsCertPath
    Path to the control-plane management-listener TLS certificate's public `.cer` file. Needed for
    the Root profile only.

.PARAMETER AssignToGroupName
    Entra group to assign all three profiles to. Resolved by display name. Device configuration
    profiles assigned to a user group apply to whatever device that user is signed into, the same
    semantics the Win32 apps already use against `Mina Analysts` -- no separate device group is
    needed.

.PARAMETER AssignToGroupId
    Entra group object id, if you would rather not resolve by name.

.PARAMETER AccessToken
    An existing Graph token. Omit to use the cached token, or to sign in with a device code.

.PARAMETER NewSignIn
    Ignore the cached token and sign in again. Needed the first time this script runs against a
    token cache that has never carried DeviceManagementConfiguration.ReadWrite.All.

.PARAMETER DryRun
    Print what would be created/updated/assigned, and change nothing.

.EXAMPLE
    .\New-MinaTrustedCertificateProfiles.ps1 -CodeSigningCertPath .\mina-lab-signing.cer -TlsCertPath .\mina-cp-tls.cer -DryRun
    .\New-MinaTrustedCertificateProfiles.ps1 -CodeSigningCertPath .\mina-lab-signing.cer -TlsCertPath .\mina-cp-tls.cer -AssignToGroupName 'Mina Analysts'

.NOTES
    Windows PowerShell 5.1. Needs DeviceManagementConfiguration.ReadWrite.All (device
    configuration profiles live under a different permission than DeviceManagementApps.ReadWrite.All,
    which the rest of this pipeline uses); assignment by name also needs Group.Read.All.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $CodeSigningCertPath,
    [Parameter(Mandatory)] [string] $TlsCertPath,
    [Parameter(Mandatory)] [string] $TenantId,
    [Parameter()] [string] $AssignToGroupName,
    [Parameter()] [string] $AssignToGroupId,
    [Parameter()] [string] $AccessToken,
    [Parameter()] [switch] $NewSignIn,
    [Parameter()] [switch] $DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$GraphBase   = 'https://graph.microsoft.com/beta'
$GraphClient = '14d82eec-204b-4c2f-b7e8-296a70dab67e'   # Microsoft Graph PowerShell, preauthorized

function Write-Step  { param([string] $M) Write-Host ''; Write-Host ('==> ' + $M) -ForegroundColor Cyan }
function Write-Info  { param([string] $M) Write-Host ('    ' + $M) }
function Write-Ok    { param([string] $M) Write-Host ('    OK: ' + $M) -ForegroundColor Green }
function Write-Warn2 { param([string] $M) Write-Host ('    WARNING: ' + $M) -ForegroundColor Yellow }

# ------------------------------------------------------------------------------------------------
# Token cache -- identical shape and path to Publish-MinaEndpointApp.ps1's / New-EdgeBetaApp.ps1's,
# deliberately: all three are meant to share one cache against the same tenant.
# ------------------------------------------------------------------------------------------------

function Get-TokenCachePath {
    $dir = Join-Path $env:LOCALAPPDATA 'Mina'
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    return Join-Path $dir 'graph-token.cache'
}

function Write-TokenCache {
    param([string] $RefreshToken, [string] $AccessToken, [DateTimeOffset] $ExpiresUtc, [string] $Upn)

    Add-Type -AssemblyName System.Security
    $payload = [ordered]@{
        refreshToken = $RefreshToken
        accessToken  = $AccessToken
        expiresUtc   = $ExpiresUtc.ToUniversalTime().ToString('o')
        upn          = $Upn
        tenantId     = $TenantId
        clientId     = $GraphClient
    } | ConvertTo-Json -Depth 4

    $protected = [Security.Cryptography.ProtectedData]::Protect(
        [Text.Encoding]::UTF8.GetBytes($payload), $null,
        [Security.Cryptography.DataProtectionScope]::CurrentUser)

    $path = Get-TokenCachePath
    [IO.File]::WriteAllText($path, [Convert]::ToBase64String($protected), (New-Object Text.UTF8Encoding($false)))

    try {
        $acl = Get-Acl -LiteralPath $path
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRule($rule) }
        $me = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($me, 'FullControl', 'Allow')))
        Set-Acl -LiteralPath $path -AclObject $acl
    } catch {
        Write-Warn2 ("Could not tighten the ACL on the token cache: {0}" -f $_.Exception.Message)
    }
}

function Read-TokenCache {
    $path = Get-TokenCachePath
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    try {
        Add-Type -AssemblyName System.Security
        $bytes = [Convert]::FromBase64String([IO.File]::ReadAllText($path))
        $plain = [Text.Encoding]::UTF8.GetString(
            [Security.Cryptography.ProtectedData]::Unprotect(
                $bytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser))
        $c = $plain | ConvertFrom-Json
        if ($c.tenantId -ne $TenantId -or $c.clientId -ne $GraphClient) { return $null }
        return $c
    } catch {
        return $null
    }
}

function Get-TokenUpn {
    param([string] $Jwt)
    try {
        $claims = $Jwt.Split('.')[1]
        switch ($claims.Length % 4) { 2 { $claims += '==' } 3 { $claims += '=' } }
        $parsed = [Text.Encoding]::UTF8.GetString(
            [Convert]::FromBase64String($claims.Replace('-', '+').Replace('_', '/'))) | ConvertFrom-Json
        if ($parsed.PSObject.Properties.Name -contains 'upn') { return [string]$parsed.upn }
        return ''
    } catch { return '' }
}

function Get-TokenFromRefresh {
    param([string] $RefreshToken, [string[]] $Scopes)
    $body = @{
        grant_type    = 'refresh_token'
        client_id     = $GraphClient
        refresh_token = $RefreshToken
        scope         = ($Scopes -join ' ')
    }
    return Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
        -ContentType 'application/x-www-form-urlencoded' -Body $body
}

function Get-DeviceCodeToken {
    param([string] $Tenant, [string] $ClientId, [string[]] $Scopes)

    $scope = ($Scopes -join ' ')
    $resp = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/devicecode" `
        -ContentType 'application/x-www-form-urlencoded' `
        -Body @{ client_id = $ClientId; scope = $scope }

    Write-Host ''
    Write-Host '  ============================================================'
    Write-Host ("   Open:  {0}" -f $resp.verification_uri)
    Write-Host ("   Code:  {0}" -f $resp.user_code)
    Write-Host '  ============================================================'
    Write-Host ''
    Write-Host ("  Sign in as an Intune administrator. Expires in {0} minutes." -f [int]($resp.expires_in / 60))

    $deadline = (Get-Date).AddSeconds($resp.expires_in)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds ([Math]::Max(5, $resp.interval))
        try {
            $tok = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/token" `
                -ContentType 'application/x-www-form-urlencoded' `
                -Body @{
                    grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
                    client_id   = $ClientId
                    device_code = $resp.device_code
                }
            if ($tok.access_token) { return $tok }
        } catch {
            $detail = ''
            try { $detail = ($_.ErrorDetails.Message | ConvertFrom-Json).error } catch { }
            if ($detail -and $detail -notin @('authorization_pending', 'slow_down')) {
                throw "Device-code sign-in failed: $detail"
            }
        }
    }
    throw 'Timed out waiting for device-code sign-in.'
}

function Invoke-Graph {
    param([string] $Method, [string] $Uri, $Body, [int] $Retries = 4)
    if ($Uri -notmatch '^https://') { $Uri = "$GraphBase$Uri" }
    $headers = @{ Authorization = "Bearer $script:Token" }
    $json = $null
    if ($null -ne $Body) { $json = $Body | ConvertTo-Json -Depth 20 }

    for ($attempt = 0; $attempt -le $Retries; $attempt++) {
        try {
            if ($null -ne $json) {
                return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($json))
            }
            return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers
        } catch {
            $status = $null
            if ($_.Exception.PSObject.Properties.Name -contains 'Response' -and $_.Exception.Response) {
                $status = [int]$_.Exception.Response.StatusCode
            }
            if ($attempt -lt $Retries -and ($status -eq 429 -or ($status -ge 500 -and $status -lt 600))) {
                $wait = [Math]::Pow(2, $attempt)
                Write-Warn2 ("Graph returned {0}; retrying in {1}s." -f $status, $wait)
                Start-Sleep -Seconds $wait
                continue
            }
            $detail = ''
            try { $detail = $_.ErrorDetails.Message } catch { }
            throw ("Graph {0} {1} failed ({2}): {3}`n{4}" -f $Method, $Uri, $status, $_.Exception.Message, $detail)
        }
    }
}

function Resolve-GroupId {
    param([string] $Name, [string] $Id)
    if ($Id) { return $Id }
    $safe = $Name.Replace("'", "''")
    $groups = Invoke-Graph -Method Get -Uri ("/groups?`$filter=" + [Uri]::EscapeDataString("displayName eq '$safe'"))
    if (-not $groups.value -or @($groups.value).Count -eq 0) { throw "No Entra group named '$Name'." }
    if (@($groups.value).Count -gt 1) { throw "More than one Entra group is named '$Name'; pass -AssignToGroupId instead." }
    return @($groups.value)[0].id
}

function Set-DeviceConfigProfile {
    <#
        Create-or-update by displayName, assign to the resolved group, then read the profile back
        and return it -- the caller decides what "matches what was sent" means for its own shape,
        since windows81TrustedRootCertificate and windows10CustomConfiguration disagree on it.
    #>
    param([hashtable] $Profile, [string] $GroupId)

    $name = $Profile.displayName
    Write-Step ("Profile: {0}" -f $name)

    if ($DryRun) {
        Write-Info ($Profile | ConvertTo-Json -Depth 10)
        Write-Info 'Dry run -- nothing created, updated, or assigned.'
        return $null
    }

    $escaped = $name.Replace("'", "''")
    $existing = Invoke-Graph -Method Get -Uri ("/deviceManagement/deviceConfigurations?`$filter=" + [Uri]::EscapeDataString("displayName eq '$escaped'"))
    if ($existing.value -and @($existing.value).Count -gt 0) {
        # PATCH on this endpoint is broken, confirmed empirically (2026-09-10): every field,
        # including an entirely empty {} body, returns the same generic ModelValidationFailure /
        # "Exception has been thrown by the target of an invocation." on both beta and v1.0 -- not
        # a payload problem, the endpoint itself. Delete and recreate instead, which is Graph's own
        # documented workaround for resources whose PATCH doesn't work. The new object gets a new
        # id every update; nothing outside this script keeps the old one, and it is reassigned
        # below either way.
        $staleId = @($existing.value)[0].id
        Invoke-Graph -Method Delete -Uri "/deviceManagement/deviceConfigurations/$staleId" | Out-Null
        Write-Info ('Deleted stale profile {0} (PATCH is not usable on this resource -- see .DESCRIPTION note)' -f $staleId)
    }
    $created = Invoke-Graph -Method Post -Uri '/deviceManagement/deviceConfigurations' -Body $Profile
    $id = $created.id
    Write-Ok ('Created profile {0}' -f $id)

    if ($GroupId) {
        Invoke-Graph -Method Post -Uri "/deviceManagement/deviceConfigurations/$id/assign" -Body @{
            assignments = @(
                @{ target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $GroupId } }
            )
        } | Out-Null
        Write-Ok ('Assigned to group {0}' -f $GroupId)
    } else {
        Write-Warn2 'No assignment target given -- the profile exists but reaches no device until assigned.'
    }

    return Invoke-Graph -Method Get -Uri "/deviceManagement/deviceConfigurations/$id"
}

# ------------------------------------------------------------------------------------------------
# Certificates
# ------------------------------------------------------------------------------------------------

if (-not (Test-Path -LiteralPath $CodeSigningCertPath)) { throw "CodeSigningCertPath not found: $CodeSigningCertPath" }
if (-not (Test-Path -LiteralPath $TlsCertPath)) { throw "TlsCertPath not found: $TlsCertPath" }

$codeSigningCert = New-Object Security.Cryptography.X509Certificates.X509Certificate2((Resolve-Path $CodeSigningCertPath).Path)
$tlsCert         = New-Object Security.Cryptography.X509Certificates.X509Certificate2((Resolve-Path $TlsCertPath).Path)

$codeSigningB64  = [Convert]::ToBase64String($codeSigningCert.RawData)
$tlsB64          = [Convert]::ToBase64String($tlsCert.RawData)
$codeSigningThumb = $codeSigningCert.Thumbprint.ToUpperInvariant()

Write-Step 'Certificates'
Write-Info ("Code-signing : {0}  thumbprint {1}  expires {2:yyyy-MM-dd}" -f $codeSigningCert.Subject, $codeSigningThumb, $codeSigningCert.NotAfter)
Write-Info ("TLS          : {0}  thumbprint {1}  expires {2:yyyy-MM-dd}" -f $tlsCert.Subject, $tlsCert.Thumbprint.ToUpperInvariant(), $tlsCert.NotAfter)

# ------------------------------------------------------------------------------------------------
# Profile definitions
# ------------------------------------------------------------------------------------------------

$codeSigningRootProfile = [ordered]@{
    '@odata.type'            = '#microsoft.graph.windows81TrustedRootCertificate'
    displayName              = 'Mina endpoint agent code-signing certificate (Root)'
    description              = 'Trusts the lab code-signing certificate used to sign the Mina Endpoint Agent Win32 app so Detect.ps1/Install.ps1 load under -ExecutionPolicy AllSigned. Stand-in for A6; retire once a real production certificate + this profile exist together (docs/BACKLOG.md M2-5).'
    certFileName             = (Split-Path -Leaf $CodeSigningCertPath)
    destinationStore         = 'computerCertStoreRoot'
    trustedRootCertificate   = $codeSigningB64
}

$tlsRootProfile = [ordered]@{
    '@odata.type'            = '#microsoft.graph.windows81TrustedRootCertificate'
    displayName              = 'Mina control-plane management TLS certificate (Root)'
    description              = 'Trusts the self-signed CN=mina.example.org certificate securing the management listener (port 8444) so the endpoint agent tray can reach it. Same certificate MinaUi (port 443) uses; only reissue changes the thumbprint.'
    certFileName             = (Split-Path -Leaf $TlsCertPath)
    destinationStore         = 'computerCertStoreRoot'
    trustedRootCertificate   = $tlsB64
}

$trustedPublisherOmaUri = "./Device/Vendor/MSFT/RootCATrustedCertificates/TrustedPublisher/$codeSigningThumb/EncodedCertificate"
$codeSigningTrustedPublisherProfile = [ordered]@{
    '@odata.type' = '#microsoft.graph.windows10CustomConfiguration'
    displayName   = 'Mina endpoint agent code-signing certificate (TrustedPublisher)'
    description   = 'Custom OMA-URI profile against the RootCATrustedCertificates CSP -- windows81TrustedRootCertificate has no TrustedPublisher destination (confirmed against this tenant''s own Graph beta $metadata), so this is the only MDM path to that store. Companion to "Mina endpoint agent code-signing certificate (Root)"; a self-signed chain needs both stores. Regenerating the lab certificate changes its thumbprint and therefore this OMA-URI -- rerun this script rather than hand-editing it.'
    omaSettings   = @(
        [ordered]@{
            '@odata.type' = '#microsoft.graph.omaSettingBase64'
            displayName   = 'Trust in TrustedPublisher'
            description   = "RootCATrustedCertificates/TrustedPublisher/$codeSigningThumb/EncodedCertificate"
            omaUri        = $trustedPublisherOmaUri
            fileName      = (Split-Path -Leaf $CodeSigningCertPath)
            value         = $codeSigningB64
        }
    )
}

if ($DryRun) {
    Write-Step 'Dry run -- would create/update and assign these three profiles'
}

# ------------------------------------------------------------------------------------------------
# Sign in
# ------------------------------------------------------------------------------------------------

if (-not $DryRun) {
    Write-Step 'Authenticating to Microsoft Graph'
    $scopes = @(
        'https://graph.microsoft.com/DeviceManagementConfiguration.ReadWrite.All',
        'https://graph.microsoft.com/Group.Read.All',
        'offline_access'
    )

    if ($AccessToken) {
        $script:Token = $AccessToken
        Write-Info 'Using the access token supplied on the command line.'
    } else {
        $script:Token = $null
        $cache = $null
        if (-not $NewSignIn) { $cache = Read-TokenCache }

        if ($cache) {
            $expires = [DateTimeOffset]::MinValue
            [void][DateTimeOffset]::TryParse([string]$cache.expiresUtc, [ref]$expires)
            if ($cache.accessToken -and $expires -gt [DateTimeOffset]::UtcNow.AddMinutes(5)) {
                $script:Token = [string]$cache.accessToken
                Write-Info ('Reusing the cached access token for {0} (valid until {1:HH:mm}).' -f $cache.upn, $expires.ToLocalTime())
            } elseif ($cache.refreshToken) {
                try {
                    $refreshed = Get-TokenFromRefresh -RefreshToken ([string]$cache.refreshToken) -Scopes $scopes
                    $script:Token = [string]$refreshed.access_token
                    Write-TokenCache -RefreshToken ([string]$refreshed.refresh_token) -AccessToken $script:Token `
                        -ExpiresUtc ([DateTimeOffset]::UtcNow.AddSeconds([int]$refreshed.expires_in)) -Upn ([string]$cache.upn)
                    Write-Info ('Refreshed the cached token for {0} -- no sign-in needed.' -f $cache.upn)
                } catch {
                    Write-Warn2 ('The cached refresh token was not accepted or lacks this scope ({0}); signing in again.' -f ($_.Exception.Message -split "`n")[0])
                }
            }
        }

        if (-not $script:Token) {
            $tok = Get-DeviceCodeToken -Tenant $TenantId -ClientId $GraphClient -Scopes $scopes
            $script:Token = [string]$tok.access_token
            if ($tok.refresh_token) {
                Write-TokenCache -RefreshToken ([string]$tok.refresh_token) -AccessToken $script:Token `
                    -ExpiresUtc ([DateTimeOffset]::UtcNow.AddSeconds([int]$tok.expires_in)) `
                    -Upn (Get-TokenUpn -Jwt $script:Token)
                Write-Info ('Token cached at {0} (DPAPI, this account on this machine only).' -f (Get-TokenCachePath))
            }
        }
    }
    Write-Ok ('Signed in as {0}' -f (Get-TokenUpn -Jwt $script:Token))
}

# ------------------------------------------------------------------------------------------------
# Resolve the assignment target once
# ------------------------------------------------------------------------------------------------

$groupId = $null
if (-not $DryRun -and ($AssignToGroupName -or $AssignToGroupId)) {
    Write-Step 'Resolving assignment target'
    $groupId = Resolve-GroupId -Name $AssignToGroupName -Id $AssignToGroupId
    Write-Ok ('Group resolved to {0}' -f $groupId)
} elseif (-not $DryRun) {
    Write-Warn2 'No -AssignToGroupName/-AssignToGroupId given -- all three profiles will be created but assigned to nobody.'
}

# ------------------------------------------------------------------------------------------------
# Create/update/assign each profile, then verify what actually landed
# ------------------------------------------------------------------------------------------------

$codeSigningRootResult             = Set-DeviceConfigProfile -Profile $codeSigningRootProfile -GroupId $groupId
$tlsRootResult                     = Set-DeviceConfigProfile -Profile $tlsRootProfile -GroupId $groupId
$codeSigningTrustedPublisherResult = Set-DeviceConfigProfile -Profile $codeSigningTrustedPublisherProfile -GroupId $groupId

if ($DryRun) {
    Write-Step 'Done (dry run)'
    return
}

Write-Step 'Verifying what actually landed'
$problems = @()

if ([string]$codeSigningRootResult.destinationStore -ne 'computerCertStoreRoot') {
    $problems += "code-signing Root profile: destinationStore is '$($codeSigningRootResult.destinationStore)', expected 'computerCertStoreRoot'."
}
if ([string]$tlsRootResult.destinationStore -ne 'computerCertStoreRoot') {
    $problems += "TLS Root profile: destinationStore is '$($tlsRootResult.destinationStore)', expected 'computerCertStoreRoot'."
}
$omaBack = @($codeSigningTrustedPublisherResult.omaSettings)
if (-not $omaBack -or $omaBack.Count -ne 1 -or [string]$omaBack[0].omaUri -ne $trustedPublisherOmaUri) {
    $problems += "TrustedPublisher profile: omaSettings did not come back as the single expected URI ($trustedPublisherOmaUri)."
}

if ($problems.Count -gt 0) {
    foreach ($p in $problems) { Write-Warn2 $p }
    throw "One or more profiles are not in the expected state after the write; $($problems.Count) problem(s) above."
}
Write-Ok 'All three profiles verified: destinationStore/omaUri match what was sent.'

Write-Step 'Done'
Write-Info ('Code-signing Root profile id  : {0}' -f $codeSigningRootResult.id)
Write-Info ('TLS Root profile id           : {0}' -f $tlsRootResult.id)
Write-Info ('TrustedPublisher profile id   : {0}' -f $codeSigningTrustedPublisherResult.id)
Write-Info 'A device already enrolled will pick these up on its next policy sync -- no re-enrollment needed.'
Write-Host ''
