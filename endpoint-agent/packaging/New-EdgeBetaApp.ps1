<#
.SYNOPSIS
    Creates or updates the Microsoft Edge (Beta channel) Intune app and assigns it (backlog M2-5).

.DESCRIPTION
    The dependency `intune-app-settings.json` has always documented as a manual step: "Deploy via
    Intune's first-party 'Microsoft Edge version 77 and later' app type with Channel = Beta, and
    mark it a required dependency of this app." That note was never automated -- a device enrolled
    fresh into this tenant has nothing that installs the research browser at all, so the Mina agent
    can apply a containment rule to a binary that never arrives (Install.ps1 exit 12).

    Unlike win32LobApp, windowsMicrosoftEdgeApp carries no content of its own -- Microsoft's own
    service manages Edge's actual distribution and updates for this channel. Creating this app is
    pure metadata: no upload, no signing, no .intunewin. Re-runnable by design, the same way
    Publish-MinaEndpointApp.ps1 is: given the same display name it finds and updates the existing
    app rather than creating a second one.

    This script only creates and assigns the app. Wiring the two Mina apps to actually depend on it
    was Publish-MinaEndpointApp.ps1's `-DependsOnAppId` parameter, run once per Mina app with this
    script's own output as the value -- kept separate because one is a one-time tenant fixture and
    the other runs on every Mina publish.

    **Do not pass this app's id to `-DependsOnAppId`.** Confirmed live on two devices (2026-09-10,
    opposite managedDeviceOwnerType, unrelated enrollment histories): Intune's own dependency
    evaluation for a windowsMicrosoftEdgeApp target reads
    `HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients\{GUID}` -- the native, non-redirected hive -- while
    EdgeUpdate itself registers there only under `WOW6432Node` (and `HKCU`) on a 64-bit OS. The
    check can never see a real install, so a dependent app never clears it: detection running
    clean and downloads completing every time, forever, with no install command ever issued. This
    is a Microsoft platform bug in the built-in check, not anything wrong with how this pipeline
    wires the relationship (the relationship write itself was verified correct and durable).
    Install.ps1's own exit 12 if the research browser is absent is the real safety net now --
    Edge Beta still gets its own Required assignment and installs on its own, independently and
    quickly, and a Mina install that races ahead of it simply retries clean on the next check-in.

.PARAMETER Channel
    dev, beta, or stable. Mina's research-browser flags and WFP containment rule are measured
    against Edge Beta specifically (M1-5); a different channel here would silently stop matching.

.PARAMETER DisplayName
    Defaults to "Microsoft Edge (Beta channel)" -- also the display name Publish-MinaEndpointApp.ps1
    looks up when resolving a dependency target by name instead of id.

.PARAMETER AssignToGroupName
    Entra group to assign the app to, as a Required install. Resolved by display name.

.PARAMETER AssignToGroupId
    Entra group object id, if you would rather not resolve by name.

.PARAMETER AccessToken
    An existing Graph token. Omit to use the cached token Publish-MinaEndpointApp.ps1 already
    maintains, or to sign in with a device code.

.PARAMETER NewSignIn
    Ignore the cached token and sign in again.

.PARAMETER DryRun
    Print the app definition and everything that would happen, and change nothing.

.EXAMPLE
    .\New-EdgeBetaApp.ps1 -DryRun
    .\New-EdgeBetaApp.ps1 -AssignToGroupName 'Mina Analysts'

.NOTES
    Windows PowerShell 5.1. Needs DeviceManagementApps.ReadWrite.All; assignment by name also needs
    Group.Read.All -- the same scopes Publish-MinaEndpointApp.ps1 already carries in its cached
    token, so running that first means this needs no separate sign-in.
#>
[CmdletBinding()]
param(
    [Parameter()] [ValidateSet('dev', 'beta', 'stable')] [string] $Channel = 'beta',
    [Parameter()] [string] $DisplayName = 'Microsoft Edge (Beta channel)',
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
# Token cache -- identical shape and path to Publish-MinaEndpointApp.ps1's, deliberately: the two
# scripts are meant to be run back to back against the same tenant, and sharing the cache means the
# second one needs no device code at all.
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

# ------------------------------------------------------------------------------------------------
# App definition
# ------------------------------------------------------------------------------------------------

$app = [ordered]@{
    '@odata.type' = '#microsoft.graph.windowsMicrosoftEdgeApp'
    displayName   = $DisplayName
    description   = 'Microsoft Edge, Beta channel -- the research browser Mina Endpoint Agent applies its containment rule to. A dependency of both Mina Endpoint Agent apps, not a general-purpose browser deployment.'
    publisher     = 'Microsoft'
    channel       = $Channel
}

Write-Step 'App definition'
Write-Host ($app | ConvertTo-Json -Depth 5)

if ($DryRun) {
    Write-Step 'Dry run'
    Write-Info 'Nothing was created, updated or assigned.'
    if ($AssignToGroupName) { Write-Info ('Would assign  : Required, to group "{0}"' -f $AssignToGroupName) }
    elseif ($AssignToGroupId) { Write-Info ('Would assign  : Required, to group id {0}' -f $AssignToGroupId) }
    else { Write-Warn2 'No assignment target given -- the app would be created but assigned to nobody.' }
    return
}

# ------------------------------------------------------------------------------------------------
# Sign in
# ------------------------------------------------------------------------------------------------

Write-Step 'Authenticating to Microsoft Graph'
$scopes = @(
    'https://graph.microsoft.com/DeviceManagementApps.ReadWrite.All',
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
                Write-Warn2 ('The cached refresh token was not accepted ({0}); signing in again.' -f ($_.Exception.Message -split "`n")[0])
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

# ------------------------------------------------------------------------------------------------
# Create or update
# ------------------------------------------------------------------------------------------------

Write-Step 'Creating or updating the app'

$escaped = $DisplayName.Replace("'", "''")
$existing = Invoke-Graph -Method Get -Uri ("/deviceAppManagement/mobileApps?`$filter=" + [Uri]::EscapeDataString("isof('microsoft.graph.windowsMicrosoftEdgeApp') and displayName eq '$escaped'"))
$appId = $null
if ($existing.value -and @($existing.value).Count -gt 0) {
    $appId = @($existing.value)[0].id
    Invoke-Graph -Method Patch -Uri "/deviceAppManagement/mobileApps/$appId" -Body $app | Out-Null
    Write-Ok ('Updated existing app {0}' -f $appId)
} else {
    $created = Invoke-Graph -Method Post -Uri '/deviceAppManagement/mobileApps' -Body $app
    $appId = $created.id
    Write-Ok ('Created app {0}' -f $appId)
}

# ------------------------------------------------------------------------------------------------
# Assign
# ------------------------------------------------------------------------------------------------

if ($AssignToGroupName -or $AssignToGroupId) {
    Write-Step 'Assigning'

    $groupId = $AssignToGroupId
    if (-not $groupId) {
        $safe = $AssignToGroupName.Replace("'", "''")
        $groups = Invoke-Graph -Method Get -Uri ("/groups?`$filter=" + [Uri]::EscapeDataString("displayName eq '$safe'"))
        if (-not $groups.value -or @($groups.value).Count -eq 0) { throw "No Entra group named '$AssignToGroupName'." }
        if (@($groups.value).Count -gt 1) { throw "More than one Entra group is named '$AssignToGroupName'; pass -AssignToGroupId instead." }
        $groupId = @($groups.value)[0].id
        Write-Info ('Group "{0}" resolved to {1}' -f $AssignToGroupName, $groupId)
    }

    Invoke-Graph -Method Post -Uri "/deviceAppManagement/mobileApps/$appId/assign" -Body @{
        mobileAppAssignments = @(
            @{
                '@odata.type' = '#microsoft.graph.mobileAppAssignment'
                intent        = 'required'
                target        = @{
                    '@odata.type' = '#microsoft.graph.groupAssignmentTarget'
                    groupId       = $groupId
                }
            }
        )
    } | Out-Null
    Write-Ok ('Assigned as a required install to {0}.' -f $groupId)
} else {
    Write-Warn2 'No assignment target given -- the app exists but will reach no device until it is assigned.'
}

# ------------------------------------------------------------------------------------------------
# Verify
# ------------------------------------------------------------------------------------------------

Write-Step 'Verifying the published app'
$final = Invoke-Graph -Method Get -Uri "/deviceAppManagement/mobileApps/$appId"
$problems = @()

$finalChannel = ''
if ($final.PSObject.Properties.Name -contains 'channel') { $finalChannel = [string]$final.channel }
if ($finalChannel -ne $Channel) { $problems += "channel is '$finalChannel', expected '$Channel'." }

if ($problems.Count -gt 0) {
    foreach ($p in $problems) { Write-Warn2 $p }
    throw "The published app is not in the expected state; $($problems.Count) problem(s) above."
}
Write-Ok ('channel {0}' -f $finalChannel)

Write-Step 'Done'
Write-Info ('App id  : {0}' -f $appId)
Write-Info 'Do not pass this id to -DependsOnAppId -- confirmed broken, see .DESCRIPTION.'
Write-Info ('Portal  : https://intune.microsoft.com/#view/Microsoft_Intune_Apps/SettingsMenu/~/0/appId/{0}' -f $appId)
Write-Host ''
