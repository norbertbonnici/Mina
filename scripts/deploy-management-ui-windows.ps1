<#
.SYNOPSIS
    Publishes Mina.ManagementUi (win-x64, framework-dependent) and (re)deploys it to the app host
    under IIS, alongside Mina.ControlPlane.Api -- entirely through the QEMU guest agent, matching
    deploy-control-plane-api-windows.ps1's approach and helper functions.

.DESCRIPTION
    The management UI is corporate-facing only (backlog M3-2) -- it is never published to the
    internet, and this script does not attempt to. It gets its own IIS site, app pool, and port on
    the same host the API runs on, firewalled to corporate ranges only, exactly the same posture
    as the API's own management listener. It shares the API's SQL login: both run on the same
    Arc-connected machine, and the Arc/HIMDS managed identity is a property of the machine, not of
    an individual process, so the app pool identity granted access to the Arc token store
    authenticates to SQL as the same machine identity the API already has a scoped login for.

    Requires the Entra app registration, app roles, group assignments, and the Federated Identity
    Credential trusting this machine's Arc identity to already exist (backlog M2-1) -- this script
    does not create any of those, it only configures the application to use them.

.PARAMETER VmId
    Proxmox VM ID of the Windows application host.

.PARAMETER ProxmoxNode
    Proxmox node the VM runs on.

.PARAMETER AppAddress
    DMZ IPv4 address of the application host (e.g. 10.20.40.91).

.PARAMETER SqlConnectionString
    Full connection string. Defaults to
    "Server=<SqlAddress>;Database=Mina;Authentication=Active Directory Default;Encrypt=True;TrustServerCertificate=True"
    against -SqlAddress, matching the API's own default.

.PARAMETER SqlAddress
    DMZ IPv4 address of the SQL Server host. Ignored if -SqlConnectionString is supplied.

.PARAMETER AzureAdTenantId
    Entra tenant ID (backlog M2-1).

.PARAMETER AzureAdClientId
    Client ID (appId) of the Mina app registration -- the UI signs in against this app directly
    (it is its own audience; there is no separate downstream API call).

.PARAMETER PublicHostname
    The DNS name analysts/managers will use, e.g. mina.bonnicilabs.com -- must match the redirect
    URI registered on the app (https://<PublicHostname>/signin-oidc) exactly. This script binds a
    self-signed certificate for this name; it does not create any DNS record -- that's a separate,
    manual step (point it at -AppAddress, and do NOT route it through any public tunnel/CDN, since
    this surface must stay off the internet per ADR-0006 constraint 1).

.PARAMETER CorpManagementCidrs
    Corporate ranges permitted to reach the UI's port, matching the API's own management-listener
    firewall rule. Default 10.20.0.0/16.

.PARAMETER UiPort
    Port the UI's HTTPS listener binds. Default 443 -- must match the port (or absence of one,
    which implies 443) in the app registration's redirect URI exactly, since Entra validates it
    strictly; 8443/8444 on this host belong to the API, so this can't reuse those either way.

.PARAMETER AppPoolName
    IIS application pool name. Default "MinaUiPool".

.PARAMETER SiteName
    IIS site name. Default "MinaUi".

.PARAMETER DeployPath
    Physical path on the guest. Default "C:\inetpub\mina-ui".
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateRange(100, 999999999)]
    [int]$VmId,

    [Parameter(Mandatory)]
    [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9\-]{0,62}$')]
    [string]$ProxmoxNode,

    [Parameter(Mandatory)]
    [ValidatePattern('^(\d{1,3}\.){3}\d{1,3}$')]
    [string]$AppAddress,

    [ValidatePattern('^(\d{1,3}\.){3}\d{1,3}$')]
    [string]$SqlAddress,

    [string]$SqlConnectionString,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$AzureAdTenantId,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$AzureAdClientId,

    [Parameter(Mandatory)]
    [ValidatePattern('^[a-zA-Z0-9.\-]{1,253}$')]
    [string]$PublicHostname,

    [ValidatePattern('^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$')]
    [string]$CorpManagementCidrs = "10.20.0.0/16",

    [ValidateRange(1, 65535)]
    [int]$UiPort = 443,

    [ValidatePattern('^[a-zA-Z0-9_-]{1,64}$')]
    [string]$AppPoolName = "MinaUiPool",

    [ValidatePattern('^[a-zA-Z0-9_-]{1,64}$')]
    [string]$SiteName = "MinaUi",

    [ValidatePattern('^[a-zA-Z]:\\[a-zA-Z0-9_\\\-]+$')]
    [string]$DeployPath = "C:\inetpub\mina-ui"
)

$ErrorActionPreference = "Stop"

if (-not $env:PROXMOX_VE_ENDPOINT -or -not $env:PROXMOX_VE_API_TOKEN) {
    throw "PROXMOX_VE_ENDPOINT and PROXMOX_VE_API_TOKEN must be set (e.g. dot-source set-proxmox-env.ps1 first)."
}

if (-not $SqlConnectionString) {
    if (-not $SqlAddress) { throw "Either -SqlConnectionString or -SqlAddress is required." }
    $SqlConnectionString = "Server=$SqlAddress;Database=Mina;Authentication=Active Directory Default;Encrypt=True;TrustServerCertificate=True"
}

# --- Proxmox API plumbing (identical to deploy-control-plane-api-windows.ps1) ---------------------
$proxmoxHost = ([Uri]$env:PROXMOX_VE_ENDPOINT).Host
if ($env:PROXMOX_VE_INSECURE -eq "true") {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {
        param($sender, $cert, $chain, $errors)
        $requestHost = $null
        if ($sender -is [System.Net.HttpWebRequest]) { $requestHost = $sender.Address.Host }
        return ($requestHost -eq $proxmoxHost)
    }
}

$baseUrl = "$($env:PROXMOX_VE_ENDPOINT.TrimEnd('/'))/api2/json"
$pveHeaders = @{ Authorization = "PVEAPIToken=$($env:PROXMOX_VE_API_TOKEN)" }

function Invoke-GuestPS {
    param([Parameter(Mandatory)][string]$Script, [int]$TimeoutTries = 60)
    $scriptBytes = [System.Text.Encoding]::Unicode.GetBytes($Script)
    $encoded = [Convert]::ToBase64String($scriptBytes)
    $jsonBody = @{ command = @("powershell.exe", "-NonInteractive", "-NoProfile", "-EncodedCommand", $encoded) } | ConvertTo-Json -Compress
    $exec = Invoke-RestMethod -Uri "$baseUrl/nodes/$ProxmoxNode/qemu/$VmId/agent/exec" -Method Post -Headers $pveHeaders -Body $jsonBody -ContentType "application/json"
    $execPid = $exec.data.pid
    if (-not $execPid) { throw "guest-agent exec did not return a pid: $($exec | ConvertTo-Json -Compress)" }
    $tries = 0
    $status = $null
    do {
        Start-Sleep -Milliseconds 1000
        try { $status = Invoke-RestMethod -Uri "$baseUrl/nodes/$ProxmoxNode/qemu/$VmId/agent/exec-status?pid=$execPid" -Method Get -Headers $pveHeaders -TimeoutSec 15 }
        catch { $status = $null }
        $tries++
    } while (($null -eq $status -or -not $status.data.exited) -and $tries -lt $TimeoutTries)
    if (-not $status) { throw "gave up polling guest-agent exec-status for pid $execPid after $TimeoutTries tries" }
    return $status.data
}

function Invoke-GuestPSChecked {
    param([Parameter(Mandatory)][string]$Script, [int]$TimeoutTries = 60)
    $result = Invoke-GuestPS -Script $Script -TimeoutTries $TimeoutTries
    if ($result.exitcode -ne 0) {
        throw "guest command failed (exitcode=$($result.exitcode)): $($result.'err-data') $($result.'out-data')"
    }
    return $result.'out-data'
}

function Submit-GuestPS {
    param([Parameter(Mandatory)][string]$Script)
    $scriptBytes = [System.Text.Encoding]::Unicode.GetBytes($Script)
    $encoded = [Convert]::ToBase64String($scriptBytes)
    $jsonBody = @{ command = @("powershell.exe", "-NonInteractive", "-NoProfile", "-EncodedCommand", $encoded) } | ConvertTo-Json -Compress
    $exec = Invoke-RestMethod -Uri "$baseUrl/nodes/$ProxmoxNode/qemu/$VmId/agent/exec" -Method Post -Headers $pveHeaders -Body $jsonBody -ContentType "application/json"
    if (-not $exec.data.pid) { throw "guest-agent exec did not return a pid: $($exec | ConvertTo-Json -Compress)" }
    return $exec.data.pid
}

function Wait-GuestFileReady {
    param([Parameter(Mandatory)][string]$Path, [int]$MaxWaitSeconds = 180, [int]$PollIntervalSeconds = 5)
    $elapsed = 0
    $lastSize = -1
    $stableCount = 0
    while ($elapsed -lt $MaxWaitSeconds) {
        Start-Sleep -Seconds $PollIntervalSeconds
        $elapsed += $PollIntervalSeconds
        $check = Invoke-GuestPS -Script "if (Test-Path '$Path') { (Get-Item '$Path').Length } else { 'MISSING' }" -TimeoutTries 15
        $out = $check.'out-data'.Trim()
        if ($out -eq 'MISSING' -or -not $out) { continue }
        $size = 0
        if ([int64]::TryParse($out, [ref]$size) -and $size -eq $lastSize -and $size -gt 0) {
            $stableCount++
            if ($stableCount -ge 2) { return $size }
        } else {
            $stableCount = 0
        }
        $lastSize = $size
    }
    throw "Wait-GuestFileReady: $Path did not stabilize within ${MaxWaitSeconds}s (last observed size: $lastSize)"
}

function Invoke-GuestPSStdin {
    param([Parameter(Mandatory)][string]$Script, [Parameter(Mandatory)][string]$StdinText, [int]$TimeoutTries = 60)
    $scriptBytes = [System.Text.Encoding]::Unicode.GetBytes($Script)
    $encoded = [Convert]::ToBase64String($scriptBytes)
    $jsonBody = @{
        command      = @("powershell.exe", "-NonInteractive", "-NoProfile", "-EncodedCommand", $encoded)
        "input-data" = $StdinText
    } | ConvertTo-Json -Compress
    $exec = Invoke-RestMethod -Uri "$baseUrl/nodes/$ProxmoxNode/qemu/$VmId/agent/exec" -Method Post -Headers $pveHeaders -Body $jsonBody -ContentType "application/json"
    $execPid = $exec.data.pid
    if (-not $execPid) { throw "guest-agent exec (stdin) did not return a pid: $($exec | ConvertTo-Json -Compress)" }
    $tries = 0
    $status = $null
    do {
        Start-Sleep -Milliseconds 500
        try { $status = Invoke-RestMethod -Uri "$baseUrl/nodes/$ProxmoxNode/qemu/$VmId/agent/exec-status?pid=$execPid" -Method Get -Headers $pveHeaders -TimeoutSec 15 }
        catch { $status = $null }
        $tries++
    } while (($null -eq $status -or -not $status.data.exited) -and $tries -lt $TimeoutTries)
    if (-not $status) { throw "gave up polling guest-agent exec-status (stdin) for pid $execPid after $TimeoutTries tries" }
    return $status.data
}

function Invoke-GuestPSStdinChecked {
    param([Parameter(Mandatory)][string]$Script, [Parameter(Mandatory)][string]$StdinText, [int]$TimeoutTries = 60)
    $result = Invoke-GuestPSStdin -Script $Script -StdinText $StdinText -TimeoutTries $TimeoutTries
    if ($result.exitcode -ne 0) {
        throw "guest command (stdin) failed (exitcode=$($result.exitcode)): $($result.'err-data') $($result.'out-data')"
    }
    return $result.'out-data'
}

# --- 1. Publish -------------------------------------------------------------------------------
Write-Host "==> Publishing Mina.ManagementUi (win-x64, framework-dependent)"
$repoRoot = Split-Path -Parent $PSScriptRoot
$publishDir = Join-Path ([System.IO.Path]::GetTempPath()) "mina-ui-publish-$([Guid]::NewGuid().ToString('N').Substring(0,8))"
New-Item -Path $publishDir -ItemType Directory -Force | Out-Null
$zipPath = "$publishDir.zip"

try {
    # A RID-specific publish must not rewrite the RID-agnostic lock files the solution restores
    # from. Directory.Build.props enables lock files for every project, so a plain
    # `dotnet publish -r win-x64` appends a net10.0/win-x64 section to every packages.lock.json in
    # the dependency graph; committing those breaks CI's `dotnet restore Mina.slnx
    # --locked-mode` with NU1004. RestorePackagesWithLockFile=false on its own is refused with
    # NU1005 while a lock file exists on disk, so NuGetLockFilePath additionally points the
    # lock-file lookup at a path that does not exist. Nothing is read from or written to it,
    # and every package version is pinned, so resolution is unchanged.
    $lockRedirect = Join-Path ([System.IO.Path]::GetTempPath()) "mina-nolock-$([Guid]::NewGuid().ToString('N').Substring(0,8)).json"
    dotnet publish (Join-Path $repoRoot "management-ui\src\Mina.ManagementUi\Mina.ManagementUi.csproj") `
        -c Release -r win-x64 --no-self-contained `
        -p:RestorePackagesWithLockFile=false -p:NuGetLockFilePath=$lockRedirect `
        -o $publishDir
    if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed with exit code $LASTEXITCODE" }

    Write-Host "==> Compressing publish output"
    Compress-Archive -Path (Join-Path $publishDir "*") -DestinationPath $zipPath -Force

    # --- 2. Transfer via Azure Blob scratch container ------------------------------------------
    $containerName = "deploy-scratch-$([Guid]::NewGuid().ToString('N').Substring(0,8))"
    $blobName = "mina-ui-publish.zip"
    Write-Host "==> Uploading publish artifact via scratch container $containerName"
    $StorageAccountName = "stminatfstatecfcfrz9v"
    az storage container create --account-name $StorageAccountName --name $containerName --auth-mode login --output none
    if ($LASTEXITCODE -ne 0) { throw "failed to create scratch container" }

    try {
        az storage blob upload --account-name $StorageAccountName --container-name $containerName `
            --name $blobName --file $zipPath --auth-mode login --overwrite true --output none
        if ($LASTEXITCODE -ne 0) { throw "failed to upload publish artifact" }

        $expiry = (Get-Date).ToUniversalTime().AddMinutes(30).ToString("yyyy-MM-ddTHH:mmZ")
        $sas = (az storage blob generate-sas --account-name $StorageAccountName --container-name $containerName `
            --name $blobName --auth-mode login --as-user --permissions r --expiry $expiry --output tsv | Out-String).Trim()
        if ($LASTEXITCODE -ne 0 -or -not $sas) { throw "failed to generate SAS for publish artifact" }
        if ($sas -match "['``\r\n]") { throw "SAS token contains an unexpected character; refusing to use it in a remote command." }
        $sasUrl = "https://$StorageAccountName.blob.core.windows.net/$containerName/${blobName}?$sas"

        Write-Host "==> Stopping app pool (if running)"
        Invoke-GuestPS -Script "Import-Module WebAdministration; Stop-WebAppPool -Name '$AppPoolName' -ErrorAction SilentlyContinue" | Out-Null

        Write-Host "==> Downloading publish artifact onto the guest"
        Invoke-GuestPS -Script "Remove-Item 'C:\Windows\Temp\mina-ui-publish.zip' -Force -ErrorAction SilentlyContinue" -TimeoutTries 15 | Out-Null
        $downloadScript = @"
`$ErrorActionPreference = 'Stop'
Invoke-WebRequest -Uri '$sasUrl' -OutFile 'C:\Windows\Temp\mina-ui-publish.zip' -UseBasicParsing
"@
        Submit-GuestPS -Script $downloadScript | Out-Null
        $downloadedSize = Wait-GuestFileReady -Path 'C:\Windows\Temp\mina-ui-publish.zip' -MaxWaitSeconds 180 -PollIntervalSeconds 5
        Write-Host "    downloaded $downloadedSize bytes"
    }
    finally {
        Write-Host "==> Removing scratch container $containerName"
        az storage container delete --account-name $StorageAccountName --name $containerName --auth-mode login --output none 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Failed to delete scratch container $containerName (exit $LASTEXITCODE) -- needs manual cleanup, but only carries a 30-minute SAS."
        }
    }

    Write-Host "==> Rebuilding $DeployPath from a clean slate"
    $deployPathLiteral = $DeployPath
    $rebuildScript = @"
`$ErrorActionPreference = 'Stop'
`$target = '$deployPathLiteral'
if (Test-Path `$target) {
    Get-ChildItem -LiteralPath `$target -Force | ForEach-Object {
        Remove-Item -LiteralPath `$_.FullName -Recurse -Force
    }
} else {
    New-Item -Path `$target -ItemType Directory -Force | Out-Null
}
Expand-Archive -Path 'C:\Windows\Temp\mina-ui-publish.zip' -DestinationPath `$target -Force
Remove-Item 'C:\Windows\Temp\mina-ui-publish.zip' -Force -ErrorAction SilentlyContinue
(Get-ChildItem `$target -Recurse -File).Count
"@
    $fileCount = (Invoke-GuestPSChecked -Script $rebuildScript -TimeoutTries 60).Trim()
    Write-Host "    $fileCount files deployed"

    Write-Host "==> Ensuring a self-signed certificate exists for $PublicHostname"
    # Self-signed, not a publicly-issued cert: this surface is corporate-network-only by design
    # (never routed through any public tunnel/CDN), so there is no public CA to issue against, and
    # matches the precedent already set by the SQL host's own self-signed certificate in this lab.
    # Entra's redirect URI validation only requires https:// scheme -- it does not itself validate
    # the certificate chain, that's the analyst's browser's concern when it lands on this page.
    $certScript = @"
`$ErrorActionPreference = 'Stop'
`$existing = @(Get-ChildItem Cert:\LocalMachine\My | Where-Object { `$_.Subject -eq 'CN=$PublicHostname' })
if (`$existing.Count -eq 0) {
    New-SelfSignedCertificate -DnsName '$PublicHostname' -CertStoreLocation Cert:\LocalMachine\My ``
        -NotAfter (Get-Date).AddYears(2) | Out-Null
    `$existing = @(Get-ChildItem Cert:\LocalMachine\My | Where-Object { `$_.Subject -eq 'CN=$PublicHostname' })
}
# .Count can be > 1 if the store already held a duplicate-subject cert from outside this script;
# pick one deterministically (newest) instead of letting member-enumeration silently produce a
# multi-line thumbprint string that would corrupt every use of it downstream.
(`$existing | Sort-Object NotAfter -Descending | Select-Object -First 1).Thumbprint
"@
    $thumbprint = (Invoke-GuestPSChecked -Script $certScript -TimeoutTries 40).Trim()
    Write-Host "    certificate thumbprint: $thumbprint"

    Write-Host "==> Ensuring app pool, site, and firewall rule match current parameters (reconciling drift)"
    $ensureScript = @"
`$ErrorActionPreference = 'Stop'
Import-Module WebAdministration

if (-not (Test-Path IIS:\AppPools\$AppPoolName)) { New-WebAppPool -Name '$AppPoolName' | Out-Null }
Set-ItemProperty IIS:\AppPools\$AppPoolName -Name managedRuntimeVersion -Value ''
Set-ItemProperty IIS:\AppPools\$AppPoolName -Name processModel.identityType -Value ApplicationPoolIdentity
Set-ItemProperty IIS:\AppPools\$AppPoolName -Name startMode -Value AlwaysRunning

if (-not (Get-Website -Name '$SiteName' -ErrorAction SilentlyContinue)) {
    New-Website -Name '$SiteName' -PhysicalPath '$deployPathLiteral' -ApplicationPool '$AppPoolName' ``
        -IPAddress '$AppAddress' -Port $UiPort -Ssl -Force | Out-Null
} else {
    Set-ItemProperty "IIS:\Sites\$SiteName" -Name physicalPath -Value '$deployPathLiteral'
}

# Reconcile the binding and its SSL certificate against current parameters, not just existence.
`$existing = @(Get-WebBinding -Name '$SiteName')
foreach (`$b in `$existing) {
    `$parts = `$b.bindingInformation -split ':'
    if (`$parts[0] -ne '$AppAddress' -or [int]`$parts[1] -ne $UiPort) {
        Remove-WebBinding -Name '$SiteName' -BindingInformation `$b.bindingInformation -Protocol `$b.protocol
    }
}
`$existing = @(Get-WebBinding -Name '$SiteName')
`$found = `$existing | Where-Object { (`$_.bindingInformation -split ':')[0] -eq '$AppAddress' -and [int](`$_.bindingInformation -split ':')[1] -eq $UiPort }
if (-not `$found) {
    New-WebBinding -Name '$SiteName' -Protocol https -IPAddress '$AppAddress' -Port $UiPort -SslFlags 0
}
`$binding = Get-WebBinding -Name '$SiteName' | Where-Object { (`$_.bindingInformation -split ':')[1] -eq '$UiPort' }
# AddSslCertificate is an HTTP.SYS *add*, not an upsert -- calling it again against an ipport that
# already has a cert bound throws ERROR_ALREADY_EXISTS (Win32 183) and would abort every redeploy
# after the first (found by review, reproduced directly against this exact primitive). Compare
# first, like every other resource reconciled in this block, and only mutate on an actual mismatch.
`$sslPath = "IIS:\SslBindings\$AppAddress!$UiPort"
`$currentCert = Get-Item `$sslPath -ErrorAction SilentlyContinue
if (-not `$currentCert) {
    `$binding.AddSslCertificate('$thumbprint', 'my')
} elseif (`$currentCert.Thumbprint -ne '$thumbprint') {
    Remove-Item `$sslPath -Force
    `$binding.AddSslCertificate('$thumbprint', 'my')
}

function Set-MinaFirewallRule(`$displayName, `$port, `$remoteAddress) {
    `$rule = Get-NetFirewallRule -DisplayName `$displayName -ErrorAction SilentlyContinue
    if (`$rule) {
        `$portFilter = `$rule | Get-NetFirewallPortFilter
        `$addrFilter = `$rule | Get-NetFirewallAddressFilter
        if ([string]`$portFilter.LocalPort -ne [string]`$port -or [string]`$addrFilter.RemoteAddress -ne [string]`$remoteAddress) {
            Remove-NetFirewallRule -DisplayName `$displayName
            `$rule = `$null
        }
    }
    if (-not `$rule) {
        New-NetFirewallRule -DisplayName `$displayName -Direction Inbound -Protocol TCP ``
            -LocalPort `$port -RemoteAddress `$remoteAddress -Action Allow -Profile Any | Out-Null
    }
}
Set-MinaFirewallRule 'Mina UI listener (corp only)' $UiPort '$CorpManagementCidrs'
'ok'
"@
    Invoke-GuestPSChecked -Script $ensureScript -TimeoutTries 40 | Out-Null

    Write-Host "==> Granting the app pool identity access to the Arc token store and data directories"
    $permsScript = @"
`$ErrorActionPreference = 'Stop'
`$identity = 'IIS AppPool\$AppPoolName'

function Grant-MinaAcl(`$path, `$rights) {
    icacls `$path /grant (`$identity + ':' + `$rights) | Out-Null
    if (`$LASTEXITCODE -ne 0) { throw "icacls /grant `$rights on `$path failed with exit code `$LASTEXITCODE" }
}

Grant-MinaAcl 'C:\ProgramData\AzureConnectedMachineAgent\Tokens' '(OI)(CI)(RX)'

`$grp = 'Hybrid agent extension applications'
if (-not (Get-LocalGroupMember -Group `$grp -ErrorAction SilentlyContinue | Where-Object { `$_.Name -eq `$identity })) {
    Add-LocalGroupMember -Group `$grp -Member `$identity
}
New-Item -Path 'C:\ProgramData\Mina\ui-dataprotection-keys' -ItemType Directory -Force | Out-Null
Grant-MinaAcl 'C:\ProgramData\Mina\ui-dataprotection-keys' '(OI)(CI)(M)'
Grant-MinaAcl '$deployPathLiteral' '(OI)(CI)(RX)'
'ok'
"@
    Invoke-GuestPSChecked -Script $permsScript -TimeoutTries 40 | Out-Null

    Write-Host "==> Writing environment configuration into web.config"
    $envVars = @{
        "ASPNETCORE_ENVIRONMENT"                                    = "Production"
        "Mina__Hosting__DataProtectionKeyPath"                      = "C:\ProgramData\Mina\ui-dataprotection-keys"
        "Mina__Hosting__ForwardedProxyCount"                        = "0"
        "ConnectionStrings__MinaDb"                                 = $SqlConnectionString
        "AzureAd__Instance"                                         = "https://login.microsoftonline.com/"
        "AzureAd__TenantId"                                         = $AzureAdTenantId
        "AzureAd__ClientId"                                         = $AzureAdClientId
        "AzureAd__CallbackPath"                                     = "/signin-oidc"
        "AzureAd__ClientCredentials__0__SourceType"                 = "SignedAssertionFromManagedIdentity"
        "AzureAd__ClientCredentials__0__TokenExchangeUrl"           = "api://AzureADTokenExchange/.default"
    }
    $envVarsJson = $envVars | ConvertTo-Json -Compress
    $webConfigScript = @"
`$ErrorActionPreference = "Stop"
`$json = [Console]::In.ReadToEnd()
`$vars = `$json | ConvertFrom-Json
`$configPath = '$deployPathLiteral\web.config'
[xml]`$doc = Get-Content `$configPath
`$aspNetCore = `$doc.configuration.location.'system.webServer'.aspNetCore
`$existing = `$aspNetCore.SelectSingleNode("environmentVariables")
if (`$existing) { `$aspNetCore.RemoveChild(`$existing) | Out-Null }
`$envVarsEl = `$doc.CreateElement("environmentVariables")
foreach (`$prop in `$vars.PSObject.Properties) {
    `$ev = `$doc.CreateElement("environmentVariable")
    `$ev.SetAttribute("name", `$prop.Name)
    `$ev.SetAttribute("value", [string]`$prop.Value)
    `$envVarsEl.AppendChild(`$ev) | Out-Null
}
`$aspNetCore.AppendChild(`$envVarsEl) | Out-Null
`$doc.Save(`$configPath)
"web.config updated with `$(`$vars.PSObject.Properties.Count) environment variables"
"@
    Invoke-GuestPSStdinChecked -Script $webConfigScript -StdinText $envVarsJson -TimeoutTries 40 | Out-Null

    Write-Host "==> Starting app pool and site"
    $startScript = @"
`$ErrorActionPreference = 'Stop'
Import-Module WebAdministration
if ((Get-WebAppPoolState -Name '$AppPoolName').Value -ne 'Started') { Start-WebAppPool -Name '$AppPoolName' }
if ((Get-WebsiteState -Name '$SiteName').Value -ne 'Started') { Start-Website -Name '$SiteName' }
'ok'
"@
    Invoke-GuestPSChecked -Script $startScript -TimeoutTries 40 | Out-Null

    # --- 3. Verify -------------------------------------------------------------------------------
    Write-Host "==> Waiting for the UI to come up and challenge for sign-in"
    $healthy = $false
    for ($i = 0; $i -lt 10; $i++) {
        Start-Sleep -Seconds 2
        $check = Invoke-GuestPS -Script @"
# Windows PowerShell 5.1 on the guest has no -SkipCertificateCheck (that's PS7+/Core only) --
# bypass validation for this self-signed cert the same way this script's own admin-side calls do.
Add-Type -TypeDefinition 'using System.Net; using System.Security.Cryptography.X509Certificates; public class TrustSelfSigned : ICertificatePolicy { public bool CheckValidationResult(ServicePoint sp, X509Certificate cert, WebRequest req, int problem) { return true; } }' -ErrorAction SilentlyContinue
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustSelfSigned
try {
    `$r = Invoke-WebRequest -Uri 'https://${AppAddress}:${UiPort}/' -UseBasicParsing -TimeoutSec 5 -MaximumRedirection 0
    `$r.StatusCode
} catch {
    if (`$_.Exception.Response) { [int]`$_.Exception.Response.StatusCode } else { 0 }
}
"@
        if ($check.'out-data'.Trim() -match '^30[1237]$') { $healthy = $true; break }
    }
    if (-not $healthy) {
        throw "Mina.ManagementUi did not respond with a sign-in redirect within 20s -- check the site's stdout log under $DeployPath\logs."
    }
    Write-Host "Mina.ManagementUi is up and correctly redirecting unauthenticated requests to sign-in."
}
finally {
    Remove-Item -Path $publishDir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $zipPath -Force -ErrorAction SilentlyContinue
}

Write-Host "==> Deploy complete. Remember: DNS for $PublicHostname -> $AppAddress is not created by this script."
