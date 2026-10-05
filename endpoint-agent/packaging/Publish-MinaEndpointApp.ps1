<#
.SYNOPSIS
    Creates or updates the Mina endpoint Win32 app in Intune, uploads the package, and assigns it
    (backlog M2-5).

.DESCRIPTION
    The half of M2-5 that Build-MinaEndpointPackage.ps1 stops short of: getting the built
    `.intunewin` into the tenant and onto devices. Everything it needs comes out of the build --
    `intune-app-settings.json` for the app definition, the signed `Detect.ps1` for the detection
    rule, the package's own `Detection.xml` for the encryption metadata Intune requires at commit
    time, and the icon the build placed beside the settings for the Company Portal tile.

    Re-runnable by design. Given the same display name it finds the existing app and adds a new
    content version rather than creating a second app, so shipping a new build is the same command
    as shipping the first one.

    **Why re-running actually updates the endpoint.** Intune decides "already installed" by running
    the app's detection script, and this project's `Detect.ps1` compares an exact version string.
    The build appends a hash of the payload to the configured version, so a package built from
    changed source -- a new tray, say -- carries a version no installed marker can match, and the
    device reinstalls. Without that, a rebuilt package uploads cleanly, reports healthy, and leaves
    the old binaries running with nothing anywhere reporting a problem.

    The upload is the fiddly part and is done the way Intune's own tooling does it: create a content
    version, declare the file, wait for Intune to hand back an Azure Storage SAS URI, upload the
    encrypted payload in blocks, commit with the file's encryption info, then point the app at the
    committed version. The SAS URI expires while a large file is still going up, so the block loop
    renews it rather than failing near the end.

.PARAMETER PackageDir
    The build's output directory -- `artifacts/intune` by default.

.PARAMETER AssignToGroupName
    Entra group to assign the app to, as a Required install. Resolved by display name.

.PARAMETER AssignToGroupId
    Entra group object id, if you would rather not resolve by name.

.PARAMETER DependsOnAppId
    App id of an Intune app this one must have installed first. Wired as an `autoInstall`
    mobileAppDependency, the same repair-checked way as the icon and the architecture properties --
    reads the relationship back and re-sends it if it drifted, rather than trusting one successful
    call. Omit to leave whatever dependency relationships already exist untouched.

    **Do not point this at the Edge Beta app (`New-EdgeBetaApp.ps1`'s output).** Confirmed live on
    two devices 2026-09-10: Intune's own dependency check for a windowsMicrosoftEdgeApp target reads
    the wrong registry hive (native, not WOW6432Node, where EdgeUpdate actually registers on a
    64-bit OS) and can never see it as installed -- a Microsoft platform bug, not a wiring problem
    on this side. The relationship was removed from both Mina apps for this reason; Install.ps1's
    own exit 12 if the research browser is absent is the ordering safety net instead. The parameter
    itself stays correct and tested for a real win32LobApp-to-win32LobApp dependency, where
    detection runs an actual script rather than this broken built-in check.

.PARAMETER AccessToken
    An existing Graph token. Omit to use the cached token, or to sign in with a device code.

.PARAMETER NewSignIn
    Ignore the cached token and sign in again, replacing it. Use after the cached refresh token has
    been revoked, or to publish as a different account.

.PARAMETER DryRun
    Print the app definition and everything that would happen, and change nothing. Use this first.

.EXAMPLE
    .\Publish-MinaEndpointApp.ps1 -DryRun
    .\Publish-MinaEndpointApp.ps1 -AssignToGroupName 'Mina Research Endpoints'

.NOTES
    Windows PowerShell 5.1. Needs DeviceManagementApps.ReadWrite.All; assignment by name also needs
    Group.Read.All.
#>
[CmdletBinding()]
param(
    [Parameter()] [string] $PackageDir,
    [Parameter(Mandatory)] [string] $TenantId,
    [Parameter()] [string] $AssignToGroupName,
    [Parameter()] [string] $AssignToGroupId,
    [Parameter()] [string] $DependsOnAppId,
    [Parameter()] [string] $AccessToken,
    [Parameter()] [switch] $ForceUpload,
    [Parameter()] [switch] $NewSignIn,
    [Parameter()] [switch] $DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$GraphBase   = 'https://graph.microsoft.com/beta'
$GraphClient = '14d82eec-204b-4c2f-b7e8-296a70dab67e'   # Microsoft Graph PowerShell, preauthorized
$BlockSize   = 4MB

if (-not $PackageDir) { $PackageDir = Join-Path (Resolve-Path (Join-Path $PSScriptRoot '..\..')) 'artifacts\intune' }

function Write-Step { param([string] $M) Write-Host ''; Write-Host ('==> ' + $M) -ForegroundColor Cyan }
function Write-Info { param([string] $M) Write-Host ('    ' + $M) }
function Write-Ok   { param([string] $M) Write-Host ('    OK: ' + $M) -ForegroundColor Green }
function Write-Warn2 { param([string] $M) Write-Host ('    WARNING: ' + $M) -ForegroundColor Yellow }

# ------------------------------------------------------------------------------------------------
# Token cache
#
# A device code lasts fifteen minutes and needs a human at the keyboard inside that window. Three
# expired unused while nobody was there, which makes re-publishing a two-person job rather than one
# command -- so the refresh token the sign-in already requests (offline_access) is kept.
#
# It is a real credential at rest, so: DPAPI at CurrentUser scope, which binds the ciphertext to
# this account on this machine (copying the file elsewhere yields nothing), under LOCALAPPDATA and
# never the repository, with the file's ACL reduced to its owner. That is the same shape as the
# `az` token cache already sitting on this workstation. It is an operator convenience on an
# administration host, and deliberately not the same thing as a secret shipped in the product --
# CLAUDE.md's "no stored credential" property is about what Mina deploys, and nothing here reaches
# an endpoint or the control plane.
#
# Refresh tokens rotate on redemption, so the new one replaces the old every time. -NewSignIn
# ignores and overwrites the cache; revoking the session in Entra invalidates it regardless.
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

    # DPAPI already binds this to the account, but a file other local accounts cannot even read is
    # one less thing to reason about.
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
        # A cache written for a different tenant or client would redeem into the wrong place.
        if ($c.tenantId -ne $TenantId -or $c.clientId -ne $GraphClient) { return $null }
        return $c
    } catch {
        # Unreadable for any reason -- a different account, a re-imaged profile, a truncated file --
        # is not an error worth stopping for. Sign in again.
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

# ------------------------------------------------------------------------------------------------
# Graph plumbing
# ------------------------------------------------------------------------------------------------

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
            # The whole response, not just the access token: the refresh token beside it is what
            # spares the next run another fifteen-minute window with a human in it.
            if ($tok.access_token) { return $tok }
        } catch {
            # authorization_pending and slow_down are the normal states while the human is signing
            # in; anything else is a real failure and should not be polled through.
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
    param(
        [string] $Method,
        [string] $Uri,
        $Body,
        [int] $Retries = 4
    )
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
            # 429 and the 5xx family are Graph being busy, not the request being wrong.
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

function Wait-ForFileState {
    <#
        Intune does the work behind a file's upload asynchronously and reports it through
        uploadState. The failure states are terminal and reported as such rather than waited out --
        polling a permanently failed upload until a timeout tells you nothing about what went wrong.
    #>
    param([string] $FileUri, [string] $Success, [int] $TimeoutSec = 300)

    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        $file = Invoke-Graph -Method Get -Uri $FileUri
        switch -Wildcard ($file.uploadState) {
            $Success    { return $file }
            '*Failed'   { throw ("Intune reported uploadState '{0}' for {1}." -f $file.uploadState, $FileUri) }
            '*TimedOut' { throw ("Intune reported uploadState '{0}' for {1}." -f $file.uploadState, $FileUri) }
        }
        Start-Sleep -Seconds 3
    }
    throw ("Timed out waiting for uploadState '{0}' on {1}." -f $Success, $FileUri)
}

function Send-BlobInBlocks {
    <#
        Uploads the encrypted package to the Azure Storage URI Intune hands back. Blocks rather than
        one PUT because the file is well past the single-shot limit, and the SAS URI is renewed
        partway because it expires on a timer that a large upload over an ordinary link will
        outlive -- that expiry lands as a 403 near the end of an otherwise fine upload, which is a
        confusing way to fail.
    #>
    param([string] $StorageUri, [string] $LocalPath, [string] $RenewUri)

    $blockIds = New-Object Collections.Generic.List[string]
    $stream = [IO.File]::OpenRead($LocalPath)
    $renewAfter = (Get-Date).AddMinutes(8)
    try {
        $buffer = New-Object byte[] $BlockSize
        $index = 0
        $sent = 0L
        $total = (Get-Item $LocalPath).Length
        while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            if ((Get-Date) -gt $renewAfter) {
                Write-Info '  renewing the storage SAS before it expires...'
                Invoke-Graph -Method Post -Uri $RenewUri | Out-Null
                $renewed = Wait-ForFileState -FileUri ($RenewUri -replace '/renewUpload$', '') -Success 'azureStorageUriRenewalSuccess'
                $StorageUri = $renewed.azureStorageUri
                $renewAfter = (Get-Date).AddMinutes(8)
            }

            $blockId = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($index.ToString('D8')))
            $blockIds.Add($blockId)

            # The last block is short, and PowerShell's array slice returns Object[] rather than
            # byte[] -- handed to Invoke-WebRequest that serialises as text and corrupts the tail of
            # the upload, which then fails its hash check at commit time rather than here. Copy into
            # a real byte[] instead of slicing.
            $chunk = $buffer
            if ($read -lt $buffer.Length) {
                $chunk = New-Object byte[] $read
                [Array]::Copy($buffer, 0, $chunk, 0, $read)
            }

            $uri = ('{0}&comp=block&blockid={1}' -f $StorageUri, [Uri]::EscapeDataString($blockId))
            Invoke-WebRequest -Method Put -Uri $uri -Headers @{ 'x-ms-blob-type' = 'BlockBlob' } `
                -Body $chunk -ContentType 'application/octet-stream' -UseBasicParsing | Out-Null

            $sent += $read
            $index++
            if ($index % 5 -eq 0 -or $sent -eq $total) {
                Write-Info ('  uploaded {0:N0} / {1:N0} bytes ({2:N0}%)' -f $sent, $total, (100 * $sent / $total))
            }
        }
    } finally {
        $stream.Dispose()
    }

    $xml = New-Object Text.StringBuilder
    [void]$xml.Append('<?xml version="1.0" encoding="utf-8"?><BlockList>')
    foreach ($id in $blockIds) { [void]$xml.AppendFormat('<Latest>{0}</Latest>', $id) }
    [void]$xml.Append('</BlockList>')

    Invoke-WebRequest -Method Put -Uri ('{0}&comp=blocklist' -f $StorageUri) `
        -Body ([Text.Encoding]::UTF8.GetBytes($xml.ToString())) -ContentType 'application/xml' -UseBasicParsing | Out-Null

    return $blockIds.Count
}

# ------------------------------------------------------------------------------------------------
# 1. Read what the build produced
# ------------------------------------------------------------------------------------------------

Write-Step 'Reading the built package'

$settingsPath = Join-Path $PackageDir 'intune-app-settings.json'
if (-not (Test-Path -LiteralPath $settingsPath)) {
    throw "No intune-app-settings.json in $PackageDir. Run Build-MinaEndpointPackage.ps1 first."
}
$settings = [IO.File]::ReadAllText($settingsPath) | ConvertFrom-Json

$detectPath = Join-Path $PackageDir 'payload\Detect.ps1'
if (-not (Test-Path -LiteralPath $detectPath)) { throw "No payload\Detect.ps1 in $PackageDir." }

# The version the package actually carries, read from the staged Detect.ps1 rather than from the
# settings file, because Detect.ps1 is what the device will compare against and it is signed.
$detectText = [IO.File]::ReadAllText($detectPath)
$versionMatch = [Regex]::Match($detectText, "ExpectedVersion\s*=\s*'(?<v>[^']+)'")
if (-not $versionMatch.Success) { throw "Could not read ExpectedVersion out of the staged Detect.ps1." }
$packageVersion = $versionMatch.Groups['v'].Value
if ($packageVersion -eq '@@PACKAGE_VERSION@@') { throw "The staged Detect.ps1 still carries the build's placeholder token." }

# Selected by version, NOT by "newest file". Those differ, and the difference is dangerous: the
# version above comes from the current payload, while the wrapped packages sitting in this directory
# are whatever previous builds left behind. Picking by timestamp could upload an older package's
# content under the current version's label -- old binaries that every device believes are new,
# which is exactly the stale-deployment failure the payload-derived version exists to prevent.
# Matching them means the two cannot disagree.
$expectedName = 'Mina-EndpointAgent-{0}.intunewin' -f $packageVersion.Replace('+', '-')
$intuneWin = Get-ChildItem -Path $PackageDir -Filter '*.intunewin' -File |
    Where-Object { $_.Name -eq $expectedName } |
    Select-Object -First 1
if (-not $intuneWin) {
    $available = (Get-ChildItem -Path $PackageDir -Filter '*.intunewin' -File | ForEach-Object { $_.Name }) -join ', '
    throw ("No package for the staged payload. Expected '{0}'; found: {1}. Re-run Build-MinaEndpointPackage.ps1 with -IntuneWinAppUtilPath so the wrap matches the payload." -f $expectedName, ($available -replace '^$', 'nothing'))
}

# Encryption metadata: unwrap the .intunewin (a zip) and read the tool's own Detection.xml.
Add-Type -AssemblyName System.IO.Compression.FileSystem
$work = Join-Path $PackageDir '.upload'
New-Item -ItemType Directory -Path $work -Force | Out-Null
$zip = [IO.Compression.ZipFile]::OpenRead($intuneWin.FullName)
try {
    foreach ($entry in $zip.Entries) {
        $dest = Join-Path $work (Split-Path -Leaf $entry.FullName)
        [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $dest, $true)
    }
} finally { $zip.Dispose() }

[xml]$detection = [IO.File]::ReadAllText((Join-Path $work 'Detection.xml'))
$appInfo = $detection.ApplicationInfo
$encryptedPayload = Join-Path $work $appInfo.FileName
$encryptionInfo = @{
    encryptionKey        = $appInfo.EncryptionInfo.EncryptionKey
    macKey               = $appInfo.EncryptionInfo.MacKey
    initializationVector = $appInfo.EncryptionInfo.InitializationVector
    mac                  = $appInfo.EncryptionInfo.Mac
    profileIdentifier    = 'ProfileVersion1'
    fileDigest           = $appInfo.EncryptionInfo.FileDigest
    fileDigestAlgorithm  = $appInfo.EncryptionInfo.FileDigestAlgorithm
}

Write-Info ('Package        : {0}' -f $intuneWin.Name)
Write-Info ('Version        : {0}' -f $packageVersion)
Write-Info ('Setup file     : {0}' -f $appInfo.SetupFile)
Write-Info ('Encrypted size : {0:N0} bytes' -f (Get-Item $encryptedPayload).Length)
Write-Info ('Unencrypted    : {0:N0} bytes' -f [long]$appInfo.UnencryptedContentSize)

# The Company Portal tile, written beside the settings by a build that knows about it (2026-09-08).
# An older settings file has no largeIconFile key -- and under strict mode that read is a
# terminating error, not $null -- so the property is only sent when the build supplied one:
# nulling it on PATCH would strip an icon the tenant already has.
$largeIcon = $null
if ($settings.PSObject.Properties.Name -contains 'largeIconFile') {
    $iconPath = Join-Path $PackageDir $settings.largeIconFile
    if (-not (Test-Path -LiteralPath $iconPath)) { throw "intune-app-settings.json names the icon '$($settings.largeIconFile)', but $iconPath does not exist." }
    # Just type and value -- the shape the Intune portal itself sends for a mimeContent. Whether
    # the property actually lands is checked in the verification step, not assumed from the PATCH.
    $largeIcon = @{
        type  = 'image/png'
        value = [Convert]::ToBase64String([IO.File]::ReadAllBytes($iconPath))
    }
    Write-Info ('Icon           : {0}' -f $iconPath)
}

# ------------------------------------------------------------------------------------------------
# 2. Build the app definition
# ------------------------------------------------------------------------------------------------

$returnCodes = @()
foreach ($rc in $settings.returnCodes) {
    $returnCodes += @{ returnCode = [int]$rc.code; type = $rc.type }
}

$payloadSha = 'not recorded'
if ($settings.PSObject.Properties.Name -contains 'payloadSha256') { $payloadSha = $settings.payloadSha256 }

# Only a build that knows about the applicableArchitectures/allowedArchitectures split (2026-09-08)
# writes this -- an older settings.json has no allowedArchitectures key at all, and strict mode
# turns that missing-property read into a terminating error rather than $null. Absent means the
# package predates the split, i.e. it is an x64-shaped build with nothing to put here.
$allowedArchitectures = $null
if ($settings.requirements.PSObject.Properties.Name -contains 'allowedArchitectures') {
    $allowedArchitectures = $settings.requirements.allowedArchitectures
}

$app = [ordered]@{
    '@odata.type'                  = '#microsoft.graph.win32LobApp'
    displayName                    = $settings.name
    description                    = $settings.description
    publisher                      = $settings.publisher
    displayVersion                 = $packageVersion
    fileName                       = $intuneWin.Name
    setupFilePath                  = $appInfo.SetupFile
    installCommandLine             = $settings.installCommandLine
    uninstallCommandLine           = $settings.uninstallCommandLine
    applicableArchitectures        = $settings.requirements.applicableArchitectures
    allowedArchitectures           = $allowedArchitectures
    minimumSupportedWindowsRelease = $settings.requirements.minimumSupportedWindowsRelease
    installExperience              = @{
        runAsAccount          = $settings.installExperience.runAsAccount
        deviceRestartBehavior = $settings.installExperience.deviceRestartBehavior
    }
    returnCodes                    = $returnCodes
    detectionRules                 = @(
        @{
            '@odata.type'         = '#microsoft.graph.win32LobAppPowerShellScriptDetection'
            enforceSignatureCheck = [bool]$settings.detectionRule.enforceSignatureCheck
            runAs32Bit            = [bool]$settings.detectionRule.runAs32Bit
            scriptContent         = [Convert]::ToBase64String([IO.File]::ReadAllBytes($detectPath))
        }
    )
    msiInformation                 = $null
    # Strict mode turns a missing property into a terminating error, and this one only exists in
    # settings files written by a build that knows about payload hashing.
    notes                          = ("Built by Build-MinaEndpointPackage.ps1. Payload SHA-256 {0}. Backlog M2-5." -f $payloadSha)
}
if ($largeIcon) { $app.largeIcon = $largeIcon }

Write-Step 'App definition'
Write-Host (($app | ConvertTo-Json -Depth 10) `
    -replace '("scriptContent"\s*:\s*")[^"]{40,}(")', '$1<base64 of the signed Detect.ps1, omitted>$2' `
    -replace '("value"\s*:\s*")[^"]{40,}(")', '$1<base64 of the icon PNG, omitted>$2')

if ($DryRun) {
    Write-Step 'Dry run'
    Write-Info 'Nothing was created, uploaded or assigned.'
    Write-Info ('Would upload  : {0}' -f $intuneWin.FullName)
    if ($AssignToGroupName) { Write-Info ('Would assign  : Required, to group "{0}"' -f $AssignToGroupName) }
    elseif ($AssignToGroupId) { Write-Info ('Would assign  : Required, to group id {0}' -f $AssignToGroupId) }
    else { Write-Warn2 'No assignment target given -- the app would be created but assigned to nobody.' }
    if ($DependsOnAppId) { Write-Info ('Would depend on: {0} (autoInstall)' -f $DependsOnAppId) }
    return
}

# ------------------------------------------------------------------------------------------------
# 3. Sign in
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
        # Five minutes of margin: a token that expires mid-upload fails somewhere far less obvious
        # than here, and a 135 MB push is long enough for that to matter.
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
                # Expired, revoked, or the account changed. Not a failure: fall through and ask.
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
# 4. Create or find the app
# ------------------------------------------------------------------------------------------------

Write-Step 'Creating or updating the app'

$escaped = $settings.name.Replace("'", "''")
$existing = Invoke-Graph -Method Get -Uri ("/deviceAppManagement/mobileApps?`$filter=" + [Uri]::EscapeDataString("isof('microsoft.graph.win32LobApp') and displayName eq '$escaped'"))
$appId = $null
$skipUpload = $false
if ($existing.value -and @($existing.value).Count -gt 0) {
    $appId = @($existing.value)[0].id
    $current = Invoke-Graph -Method Get -Uri "/deviceAppManagement/mobileApps/$appId"

    # displayVersion carries the payload hash, so "same version, already committed" means the
    # content in the tenant is the content in this package. Re-uploading 135 MB to arrive at the
    # same bytes is waste, and it makes re-running the script after a metadata-only change --
    # a corrected command line, say -- something to avoid rather than something safe to do.
    $committed = ''
    if ($current.PSObject.Properties.Name -contains 'committedContentVersion') { $committed = [string]$current.committedContentVersion }
    $currentVersion = ''
    if ($current.PSObject.Properties.Name -contains 'displayVersion') { $currentVersion = [string]$current.displayVersion }

    if ($currentVersion -eq $packageVersion -and -not [string]::IsNullOrWhiteSpace($committed)) {
        $skipUpload = $true
        Write-Info ('App {0} already serves {1} (content version {2}); updating metadata only.' -f $appId, $packageVersion, $committed)
        Write-Info 'Pass -ForceUpload to push the content again anyway.'
    } else {
        Write-Info ('Found existing app {0} at version "{1}"; adding a new content version for "{2}".' -f $appId, $currentVersion, $packageVersion)
    }
    if ($ForceUpload) { $skipUpload = $false; Write-Info 'ForceUpload given; re-uploading the content.' }

    # applicableArchitectures is settable on create but NOT by PATCH -- Graph answers 400 with
    # "can only be set via ODataAction: enableApplicableArchitectures". Sending it in an update body
    # therefore fails the whole PATCH, and every other property with it, so it is filtered out here
    # and applied through its own action below when it actually differs. allowedArchitectures is
    # excluded the same way, defensively: it is documented (2026-09-08) as the newer property that
    # actually accepts arm64, where applicableArchitectures does not, but nothing yet proves it
    # survives a PATCH the way applicableArchitectures provably does not -- the verification step
    # below checks it after every run and repairs it if this caution turns out to be justified,
    # which is how applicableArchitectures's own PATCH-clearing was originally found.
    $patch = [ordered]@{}
    foreach ($key in $app.Keys) {
        if ($key -notin @('applicableArchitectures', 'allowedArchitectures')) { $patch[$key] = $app[$key] }
    }
    Invoke-Graph -Method Patch -Uri "/deviceAppManagement/mobileApps/$appId" -Body $patch | Out-Null

    # applicableArchitectures is repaired at the very end rather than here -- see the note before
    # the verification step. Every PATCH clears it, including the committedContentVersion one that
    # comes after the upload, so fixing it at this point only means fixing it too early.
} else {
    $created = Invoke-Graph -Method Post -Uri '/deviceAppManagement/mobileApps' -Body $app
    $appId = $created.id
    Write-Ok ('Created app {0}' -f $appId)
}

# ------------------------------------------------------------------------------------------------
# 5. Upload the content
# ------------------------------------------------------------------------------------------------

if ($skipUpload) {
    Write-Step 'Uploading the package'
    Write-Ok 'Skipped -- the tenant already holds this exact payload.'
} else {

Write-Step 'Uploading the package'

$appPath = "/deviceAppManagement/mobileApps/$appId/microsoft.graph.win32LobApp"
$version = Invoke-Graph -Method Post -Uri "$appPath/contentVersions" -Body @{}
Write-Info ('Content version {0}' -f $version.id)

$fileBody = @{
    '@odata.type'   = '#microsoft.graph.mobileAppContentFile'
    name            = $appInfo.FileName
    size            = [long]$appInfo.UnencryptedContentSize
    sizeEncrypted   = (Get-Item $encryptedPayload).Length
    manifest        = $null
    isDependency    = $false
}
$file = Invoke-Graph -Method Post -Uri "$appPath/contentVersions/$($version.id)/files" -Body $fileBody
$fileUri = "$appPath/contentVersions/$($version.id)/files/$($file.id)"

$ready = Wait-ForFileState -FileUri $fileUri -Success 'azureStorageUriRequestSuccess'
Write-Info 'Intune returned an Azure Storage URI; uploading blocks...'

$blocks = Send-BlobInBlocks -StorageUri $ready.azureStorageUri -LocalPath $encryptedPayload -RenewUri "$fileUri/renewUpload"
Write-Ok ('Uploaded {0} blocks.' -f $blocks)

Invoke-Graph -Method Post -Uri "$fileUri/commit" -Body @{ fileEncryptionInfo = $encryptionInfo } | Out-Null
Wait-ForFileState -FileUri $fileUri -Success 'commitFileSuccess' -TimeoutSec 600 | Out-Null
Write-Ok 'Content committed.'

Invoke-Graph -Method Patch -Uri "/deviceAppManagement/mobileApps/$appId" -Body @{
    '@odata.type'            = '#microsoft.graph.win32LobApp'
    committedContentVersion  = $version.id
} | Out-Null
Write-Ok ('App {0} now serves content version {1}.' -f $appId, $version.id)

}

# ------------------------------------------------------------------------------------------------
# 6. Assign
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
                settings      = @{
                    '@odata.type'              = '#microsoft.graph.win32LobAppAssignmentSettings'
                    notifications              = 'showAll'
                    deliveryOptimizationPriority = 'notConfigured'
                }
            }
        )
    } | Out-Null
    Write-Ok ('Assigned as a required install to {0}.' -f $groupId)
} else {
    Write-Warn2 'No assignment target given -- the app exists but will reach no device until it is assigned.'
}

# ------------------------------------------------------------------------------------------------
# 7. Verify what the tenant actually holds
# ------------------------------------------------------------------------------------------------

# Read the app back rather than trusting the calls that got here. Two of the failures this script
# was written around -- an architecture silently cleared to "none", and a version label that moved
# ahead of the content it names -- both leave an app that reports as healthy and reaches no device.
# Neither is visible without looking.
Write-Step 'Verifying the published app'

# The Company Portal icon first, because it is repaired by PATCH and every PATCH clears
# applicableArchitectures (repaired next). Measured 2026-09-08: the icon sent in the metadata
# PATCH survives a metadata-only run, but a run that uploads content -- whose closing PATCH sets
# committedContentVersion -- leaves the app with no icon at all. Read it back; put it back.
if ($largeIcon) {
    $iconNow = Invoke-Graph -Method Get -Uri "/deviceAppManagement/mobileApps/${appId}?`$select=largeIcon"
    $storedIcon = ''
    if ($iconNow.PSObject.Properties.Name -contains 'largeIcon' -and $iconNow.largeIcon -and $iconNow.largeIcon.value) {
        $storedIcon = [string]$iconNow.largeIcon.value
    }
    if ($storedIcon -ne $largeIcon.value) {
        Invoke-Graph -Method Patch -Uri "/deviceAppManagement/mobileApps/$appId" -Body @{
            '@odata.type' = '#microsoft.graph.win32LobApp'
            largeIcon     = $largeIcon
        } | Out-Null
        Write-Info ('Restored the Company Portal icon (the tenant held {0}).' -f $(if ($storedIcon) { 'a different image' } else { 'none' }))
    }
}

# allowedArchitectures is the newer property (2026-09-08) that actually accepts arm64, where
# applicableArchitectures does not. Whether it survives a PATCH the way applicableArchitectures
# provably does not is not yet established -- this checks it the same defensive way and repairs via
# a direct PATCH if it drifted, since no dedicated action for it is documented. If that PATCH itself
# is refused, this reports it as a real problem below rather than swallowing it, which is exactly
# the evidence needed to design a proper fix instead of guessing at one.
#
# It goes BEFORE the applicableArchitectures check: its PATCH is one more PATCH that clears
# applicableArchitectures, and it sets it to "none" as a side effect -- which, since every build now
# declares itself through allowedArchitectures alone, is exactly the value expected there. A stale
# allowedArchitectures is also the one that matters: on 2026-09-08 the x64 app was found holding
# "x64,arm64" -- what the portal shows and what targeting uses -- because nothing here managed it.
$desiredAllowed = ''
if ($allowedArchitectures) { $desiredAllowed = [string]$allowedArchitectures }
$beforeRepair = Invoke-Graph -Method Get -Uri "/deviceAppManagement/mobileApps/$appId"
if ($desiredAllowed) {
    $currentAllowed = ''
    if ($beforeRepair.PSObject.Properties.Name -contains 'allowedArchitectures' -and $beforeRepair.allowedArchitectures) {
        $currentAllowed = [string]$beforeRepair.allowedArchitectures
    }
    if ($currentAllowed -ne $desiredAllowed) {
        try {
            Invoke-Graph -Method Patch -Uri "/deviceAppManagement/mobileApps/$appId" -Body @{
                '@odata.type'         = '#microsoft.graph.win32LobApp'
                allowedArchitectures  = $desiredAllowed
            } | Out-Null
            Write-Info ('Restored allowedArchitectures to {0} via a direct PATCH (it read "{1}").' -f $desiredAllowed, $currentAllowed)
        } catch {
            Write-Warn2 ("Could not repair allowedArchitectures via PATCH: {0}" -f (($_.Exception.Message) -split "`n")[0])
        }
    }
}

# applicableArchitectures is repaired here, last, because EVERY PATCH clears it to "none" -- not
# only the metadata update, but also the committedContentVersion PATCH that follows the upload.
# Measured on 2026-09-06: repairing it straight after the first PATCH looked right and was undone
# minutes later by the second, and the verification below is what caught that. It is set through
# its own OData action because Graph refuses it in a PATCH body at all. "none" cannot be requested
# through that action; it is what a PATCH leaves behind, so a build that expects it (every build
# since 2026-09-08) is simply read back below and reported if it is anything else.
$desiredArch = [string]$settings.requirements.applicableArchitectures
$afterAllowed = Invoke-Graph -Method Get -Uri "/deviceAppManagement/mobileApps/$appId"
$currentArch = ''
if ($afterAllowed.PSObject.Properties.Name -contains 'applicableArchitectures') { $currentArch = [string]$afterAllowed.applicableArchitectures }
if ($currentArch -ne $desiredArch -and $desiredArch -ne 'none') {
    Invoke-Graph -Method Post `
        -Uri "/deviceAppManagement/mobileApps/$appId/microsoft.graph.win32LobApp/enableApplicableArchitectures" `
        -Body @{ applicableArchitectures = $desiredArch } | Out-Null
    Write-Info ('Restored applicableArchitectures to {0} (a PATCH had left it "{1}").' -f $desiredArch, $currentArch)
}

# A dependency is a relationship object, not a property on the app -- it does not live behind
# $select on the app itself and a PATCH cannot touch it, so it needs its own read and (unlike
# allowedArchitectures) has no reason to expect the PATCH-clearing quirk the other properties have.
# Checked and repaired the same way regardless: an assumption resting on "it probably survives" is
# exactly how applicableArchitectures's own silent reset went unnoticed for as long as it did.
if ($DependsOnAppId) {
    $currentRelationships = Invoke-Graph -Method Get -Uri "/deviceAppManagement/mobileApps/$appId/relationships"
    $existingDependency = $null
    if ($currentRelationships.value) {
        $existingDependency = $currentRelationships.value | Where-Object {
            $_.'@odata.type' -eq '#microsoft.graph.mobileAppDependency' -and $_.targetId -eq $DependsOnAppId
        } | Select-Object -First 1
    }
    if (-not $existingDependency -or $existingDependency.dependencyType -ne 'autoInstall') {
        Invoke-Graph -Method Post -Uri "/deviceAppManagement/mobileApps/$appId/updateRelationships" -Body @{
            relationships = @(
                @{
                    '@odata.type'  = '#microsoft.graph.mobileAppDependency'
                    targetId       = $DependsOnAppId
                    targetType     = 'parent'
                    dependencyType = 'autoInstall'
                }
            )
        } | Out-Null
        Write-Info ('Set the {0} dependency on {1} (autoInstall).' -f $(if ($existingDependency) { 'drifted' } else { 'missing' }), $DependsOnAppId)
    }
}

$final = Invoke-Graph -Method Get -Uri "/deviceAppManagement/mobileApps/$appId"
$problems = @()

if ($DependsOnAppId) {
    $finalRelationships = Invoke-Graph -Method Get -Uri "/deviceAppManagement/mobileApps/$appId/relationships"
    $finalDependency = $null
    if ($finalRelationships.value) {
        $finalDependency = $finalRelationships.value | Where-Object {
            $_.'@odata.type' -eq '#microsoft.graph.mobileAppDependency' -and $_.targetId -eq $DependsOnAppId
        } | Select-Object -First 1
    }
    if (-not $finalDependency -or $finalDependency.dependencyType -ne 'autoInstall') {
        $problems += "No autoInstall dependency on $DependsOnAppId -- the research browser would not be installed for a device that has neither."
    }
}

if ($largeIcon) {
    $finalIcon = Invoke-Graph -Method Get -Uri "/deviceAppManagement/mobileApps/${appId}?`$select=largeIcon"
    $hasIcon = $finalIcon.PSObject.Properties.Name -contains 'largeIcon' -and $finalIcon.largeIcon -and $finalIcon.largeIcon.value
    if (-not $hasIcon) {
        $problems += 'largeIcon is missing -- the Company Portal tile would show no icon.'
    }
}

$finalArch = ''
if ($final.PSObject.Properties.Name -contains 'applicableArchitectures') { $finalArch = [string]$final.applicableArchitectures }
if ($finalArch -ne $desiredArch) {
    $problems += "applicableArchitectures is '$finalArch', expected '$desiredArch' -- the app would apply to no device."
}

if ($desiredAllowed) {
    $finalAllowed = ''
    if ($final.PSObject.Properties.Name -contains 'allowedArchitectures' -and $final.allowedArchitectures) { $finalAllowed = [string]$final.allowedArchitectures }
    if ($finalAllowed -ne $desiredAllowed) {
        $problems += "allowedArchitectures is '$finalAllowed', expected '$desiredAllowed' -- the app would apply to no device."
    }
}

$finalVersion = ''
if ($final.PSObject.Properties.Name -contains 'displayVersion') { $finalVersion = [string]$final.displayVersion }
if ($finalVersion -ne $packageVersion) {
    $problems += "displayVersion is '$finalVersion', expected '$packageVersion'."
}

$finalCommitted = ''
if ($final.PSObject.Properties.Name -contains 'committedContentVersion') { $finalCommitted = [string]$final.committedContentVersion }
if ([string]::IsNullOrWhiteSpace($finalCommitted)) {
    $problems += 'No committed content version -- the app has no content to install.'
}

if ($problems.Count -gt 0) {
    foreach ($p in $problems) { Write-Warn2 $p }
    throw "The published app is not in the expected state; $($problems.Count) problem(s) above."
}
$archSummary = $finalArch
if ($desiredAllowed) { $archSummary = ('{0} (allowedArchitectures={1})' -f $finalArch, $finalAllowed) }
Write-Ok ('architectures {0}, version {1}, content version {2}' -f $archSummary, $finalVersion, $finalCommitted)

Write-Step 'Done'
Write-Info ('App id  : {0}' -f $appId)
Write-Info ('Version : {0}' -f $packageVersion)
Write-Info ('Portal  : https://intune.microsoft.com/#view/Microsoft_Intune_Apps/SettingsMenu/~/0/appId/{0}' -f $appId)
Write-Host ''
