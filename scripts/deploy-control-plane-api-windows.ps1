<#
.SYNOPSIS
    Publishes Mina.ControlPlane.Api (win-x64, framework-dependent) and (re)deploys it to the
    Windows/IIS application host, entirely through the QEMU guest agent -- there is no RDP/WinRM
    surface on these hosts by design, matching the "no interactive remote admin" posture the SQL
    host and this app host were both built under.

.DESCRIPTION
    Mirrors deploy-control-plane-api.sh's shape and guarantees for the Windows/IIS host that
    replaced the original Linux/systemd one (see app-onprem-windows's module header for why):
    idempotent (safe to re-run), clean-slate (removes what a previous deploy left before writing
    the new one, so a file dropped from the build never lingers), and fails closed on bad input
    rather than splicing it unvalidated into a remotely-executed script.

    Mina:AllowDevelopmentFallbacks=true is still the only way this process starts at all, but now
    only because of the audit export sink (backlog M4-19): the Key Vault-backed CA exists since
    M2-2c, and -CaKeyVaultUri points this host at it so session certificates are signed by a key it
    cannot read. Without that parameter the ephemeral CA is still used and still regenerates on
    every restart. Unlike the first Linux deployment, SQL persistence is expected to be
    configured (-SqlAddress), because M4-18 (SQL Server + Arc) has landed -- this script requires
    it rather than falling back to in-memory state silently.

.PARAMETER VmId
    Proxmox VM ID of the Windows application host (see `terraform output app_vm_id`).

.PARAMETER ProxmoxNode
    Proxmox node the VM runs on (e.g. "red").

.PARAMETER AppAddress
    DMZ IPv4 address of the application host (e.g. 10.20.40.91). Used for post-deploy health
    checks, not for anything Terraform-managed.

.PARAMETER SqlAddress
    DMZ IPv4 address of the SQL Server host (e.g. 10.20.40.92). Used to build the default
    connection string; ignored if -SqlConnectionString is supplied directly.

.PARAMETER ProxyAddress
    DMZ IPv4 address of the publishing reverse proxy (e.g. 10.20.40.90) -- the only address the
    node-facing Windows Firewall rule admits. Security-relevant: get this wrong and the node port
    either rejects the real proxy or admits the wrong host.

.PARAMETER SqlConnectionString
    Full connection string override. Defaults to
    "Server=<SqlAddress>;Database=Mina;Authentication=Active Directory Default;Encrypt=True;TrustServerCertificate=True"
    -- Entra managed-identity auth, no stored credential (SR-005). TrustServerCertificate is
    required here because the SQL host uses a self-signed certificate in this environment; drop it
    once that host has a certificate issued by something the client trusts.

.PARAMETER AzureAdTenantId
    Entra tenant ID the API validates bearer tokens against (backlog M2-1). Optional -- omit to
    leave the checked-in appsettings.json placeholder in place (the API starts, but every
    JWT-bearer-protected endpoint rejects real tokens until this is set).

.PARAMETER AzureAdClientId
    Client ID (appId) of the Mina app registration the API validates as audience. The API is a
    pure resource server here -- it validates incoming bearer tokens, it does not itself act as a
    confidential client, so no client credential is needed on this side (that's only required by
    the management UI's own sign-in flow, a separate deployment).

.PARAMETER RequiredAuthContextId
    Conditional Access authentication context ID (e.g. "c1") session issuance must request,
    completing backlog M2-1's second half (ARCHITECTURE.md §4). Optional -- the check is already
    implemented and tested in code, but stays inert (no context required) until this is set, which
    itself requires the authentication context and its bound CA policy to exist in the tenant
    first (see scripts/finish-m2-1-conditional-access.sh).

.PARAMETER NodePort
    Port for the internet-published, node-facing listener. Default 8443.

.PARAMETER ManagementPort
    Port for the corporate-facing listener. Default 8444.

.PARAMETER StorageAccountName
    Azure Storage account used as a scratch transfer channel for the published build (Proxmox's
    own agent/exec API has a request-body ceiling well under 100KB -- unusable for a multi-MB
    publish output; see feedback memory for the measured threshold). Needs Storage Blob Data
    Contributor (or better) for the signed-in az CLI principal; a throwaway container is created,
    used, and deleted within this account on every run.

.PARAMETER AppPoolName
    IIS application pool name. Default "MinaApiPool".

.PARAMETER SiteName
    IIS site name. Default "MinaApi".

.PARAMETER DeployPath
    Physical path on the guest the site is rooted at. Default "C:\inetpub\mina-api".

.EXAMPLE
    .\deploy-control-plane-api-windows.ps1 -VmId 114 -ProxmoxNode red `
        -AppAddress 10.20.40.91 -SqlAddress 10.20.40.92

    Requires PROXMOX_VE_ENDPOINT / PROXMOX_VE_API_TOKEN (and PROXMOX_VE_INSECURE if the host's
    certificate isn't otherwise trusted) to already be set -- e.g. by dot-sourcing
    set-proxmox-env.ps1, the same env vars Terraform itself uses.
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

    [Parameter(Mandatory)]
    [ValidatePattern('^(\d{1,3}\.){3}\d{1,3}$')]
    [string]$SqlAddress,

    [Parameter(Mandatory)]
    [ValidatePattern('^(\d{1,3}\.){3}\d{1,3}$')]
    [string]$ProxyAddress,

    [string]$SqlConnectionString,

    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$AzureAdTenantId,

    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$AzureAdClientId,

    [ValidatePattern('^c[0-9]{1,3}$')]
    [string]$RequiredAuthContextId,

    # The internal CA's vault (M2-2c) -- `terraform output -raw key_vault_uri`. Set it and this
    # host signs session certificates with a key it cannot read, using its own Arc managed
    # identity; leave it unset and it uses the ephemeral development CA, which regenerates on
    # every restart. Setting it before the CA has been bootstrapped (`mina-ca bootstrap`), or
    # before this host's identity holds Key Vault Crypto User and Secrets User, makes the API
    # refuse to start -- deliberately, because the alternative is a host that starts and cannot
    # issue a certificate.
    [ValidatePattern('^https://[a-z0-9-]{3,24}\.vault\.azure\.net/?$')]
    [string]$CaKeyVaultUri,

    [ValidateRange(1, 65535)]
    [int]$NodePort = 8443,

    [ValidateRange(1, 65535)]
    [int]$ManagementPort = 8444,

    [Parameter(Mandatory)]
    [ValidatePattern('^[a-z0-9]{3,24}$')]
    [string]$StorageAccountName,

    [ValidatePattern('^[a-zA-Z0-9_-]{1,64}$')]
    [string]$AppPoolName = "MinaApiPool",

    [ValidatePattern('^[a-zA-Z0-9_-]{1,64}$')]
    [string]$SiteName = "MinaApi",

    [ValidatePattern('^[a-zA-Z]:\\[a-zA-Z0-9_\\\-]+$')]
    [string]$DeployPath = "C:\inetpub\mina-api"
)

$ErrorActionPreference = "Stop"

if ($NodePort -eq $ManagementPort) {
    throw "NodePort and ManagementPort must differ -- one port would publish the management surface to the internet."
}

if (-not $env:PROXMOX_VE_ENDPOINT -or -not $env:PROXMOX_VE_API_TOKEN) {
    throw "PROXMOX_VE_ENDPOINT and PROXMOX_VE_API_TOKEN must be set (e.g. dot-source set-proxmox-env.ps1 first)."
}

if (-not $SqlConnectionString) {
    $SqlConnectionString = "Server=$SqlAddress;Database=Mina;Authentication=Active Directory Default;Encrypt=True;TrustServerCertificate=True"
}

# --- Proxmox API plumbing ------------------------------------------------------------------------
# Scoped certificate trust: only the Proxmox host's own self-signed cert is exempted, not every
# HTTPS call this process makes (a blanket ICertificatePolicy override would also silently waive
# validation for the Azure calls below, which is not a trade this script should make quietly).
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
    <# Runs a PowerShell script on the guest via the QEMU agent and waits for it to exit.
       Returns the agent's exec-status data (out-data/err-data/exitcode/exited). #>
    param(
        [Parameter(Mandatory)][string]$Script,
        [int]$TimeoutTries = 60
    )
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

function Submit-GuestPS {
    <# Starts a PowerShell script on the guest and returns immediately with its pid -- does not
       wait for or poll exec-status. Use for long-running commands (a multi-MB download) paired
       with Wait-GuestFileReady, since exec-status polling has been observed to give up on this
       guest agent for commands that take real wall-clock time, even though the command itself
       completes fine (see feedback memory). #>
    param([Parameter(Mandatory)][string]$Script)
    $scriptBytes = [System.Text.Encoding]::Unicode.GetBytes($Script)
    $encoded = [Convert]::ToBase64String($scriptBytes)
    $jsonBody = @{ command = @("powershell.exe", "-NonInteractive", "-NoProfile", "-EncodedCommand", $encoded) } | ConvertTo-Json -Compress
    $exec = Invoke-RestMethod -Uri "$baseUrl/nodes/$ProxmoxNode/qemu/$VmId/agent/exec" -Method Post -Headers $pveHeaders -Body $jsonBody -ContentType "application/json"
    if (-not $exec.data.pid) { throw "guest-agent exec did not return a pid: $($exec | ConvertTo-Json -Compress)" }
    return $exec.data.pid
}

function Wait-GuestFileReady {
    <# Polls the guest (via small, fast, independent exec calls -- not the long-running command's
       own exec-status) until $Path exists and its size has stopped changing across two
       consecutive checks, or $MaxWaitSeconds elapses. Confirms completion by observable result,
       not by trusting a single flaky status channel. #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$MaxWaitSeconds = 180,
        [int]$PollIntervalSeconds = 5
    )
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

function Invoke-GuestPSChecked {
    <# Invoke-GuestPS, but throws on a nonzero PowerShell exit code so failures stop the deploy
       instead of silently continuing (the guest agent's own "exited" flag means the process
       finished, not that it succeeded). Includes err-data in the thrown message -- a terminating
       guest-side error's actual text lands there, not in out-data, which is frequently empty for
       an early failure. #>
    param([Parameter(Mandatory)][string]$Script, [int]$TimeoutTries = 60)
    $result = Invoke-GuestPS -Script $Script -TimeoutTries $TimeoutTries
    if ($result.exitcode -ne 0) {
        throw "guest command failed (exitcode=$($result.exitcode)): $($result.'err-data') $($result.'out-data')"
    }
    return $result.'out-data'
}

function Invoke-GuestPSStdin {
    <# Like Invoke-GuestPS, but feeds $StdinText to the child process's stdin via Proxmox's
       input-data field. IMPORTANT: input-data takes the raw text -- Proxmox base64-encodes it
       before handing it to the underlying QEMU GA call. Pre-encoding $StdinText yourself
       double-encodes it. #>
    param(
        [Parameter(Mandatory)][string]$Script,
        [Parameter(Mandatory)][string]$StdinText,
        [int]$TimeoutTries = 60
    )
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
    <# Invoke-GuestPSStdin, but throws on a nonzero exit code -- see Invoke-GuestPSChecked. #>
    param([Parameter(Mandatory)][string]$Script, [Parameter(Mandatory)][string]$StdinText, [int]$TimeoutTries = 60)
    $result = Invoke-GuestPSStdin -Script $Script -StdinText $StdinText -TimeoutTries $TimeoutTries
    if ($result.exitcode -ne 0) {
        throw "guest command (stdin) failed (exitcode=$($result.exitcode)): $($result.'err-data') $($result.'out-data')"
    }
    return $result.'out-data'
}

# --- 1. Publish -------------------------------------------------------------------------------
Write-Host "==> Publishing Mina.ControlPlane.Api (win-x64, framework-dependent)"
$repoRoot = Split-Path -Parent $PSScriptRoot
$publishDir = Join-Path ([System.IO.Path]::GetTempPath()) "mina-win-publish-$([Guid]::NewGuid().ToString('N').Substring(0,8))"
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
    dotnet publish (Join-Path $repoRoot "control-plane\src\Mina.ControlPlane.Api\Mina.ControlPlane.Api.csproj") `
        -c Release -r win-x64 --no-self-contained `
        -p:RestorePackagesWithLockFile=false -p:NuGetLockFilePath=$lockRedirect `
        -o $publishDir
    if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed with exit code $LASTEXITCODE" }

    Write-Host "==> Compressing publish output"
    Compress-Archive -Path (Join-Path $publishDir "*") -DestinationPath $zipPath -Force

    # --- 2. Transfer via Azure Blob scratch container ------------------------------------------
    # Proxmox's agent/exec has a request-body ceiling well under 100KB -- fine for scripts, not
    # for a multi-MB publish output. Route through blob storage instead: the VM already has
    # outbound internet (proven by the Arc/hosting-bundle installs), and a user-delegation SAS
    # works even though this storage account has shared-key auth disabled.
    $containerName = "deploy-scratch-$([Guid]::NewGuid().ToString('N').Substring(0,8))"
    $blobName = "mina-api-publish.zip"
    Write-Host "==> Uploading publish artifact via scratch container $containerName"
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
        # $sas is the one value in this script spliced into a remotely-executed script string
        # without a [ValidatePattern]-protected parameter behind it -- confirm it can't contain
        # anything that would break out of the single-quoted -Uri argument on the guest side.
        if ($sas -match "['``\r\n]") { throw "SAS token contains an unexpected character; refusing to use it in a remote command." }
        $sasUrl = "https://$StorageAccountName.blob.core.windows.net/$containerName/${blobName}?$sas"

        # --- 3. Guest side: stop, download, expand, wire config, restart -----------------------
        Write-Host "==> Stopping app pool (if running)"
        Invoke-GuestPS -Script "Import-Module WebAdministration; Stop-WebAppPool -Name '$AppPoolName' -ErrorAction SilentlyContinue" | Out-Null

        Write-Host "==> Downloading publish artifact onto the guest"
        # Fire-and-forget + poll-for-result rather than Invoke-GuestPSChecked: exec-status
        # polling has been observed to give up on this specific step (a several-MB download
        # taking real wall-clock time under guest I/O load) even though the download itself
        # completes fine every time (verified manually, repeatedly). Wait-GuestFileReady confirms
        # completion by the actual file size stabilizing, checked via fresh, fast, independent
        # calls, instead of trusting one long-running command's own status channel.
        Invoke-GuestPS -Script "Remove-Item 'C:\Windows\Temp\mina-api-publish.zip' -Force -ErrorAction SilentlyContinue" -TimeoutTries 15 | Out-Null
        $downloadScript = @"
`$ErrorActionPreference = 'Stop'
Invoke-WebRequest -Uri '$sasUrl' -OutFile 'C:\Windows\Temp\mina-api-publish.zip' -UseBasicParsing
"@
        Submit-GuestPS -Script $downloadScript | Out-Null
        $downloadedSize = Wait-GuestFileReady -Path 'C:\Windows\Temp\mina-api-publish.zip' -MaxWaitSeconds 180 -PollIntervalSeconds 5
        Write-Host "    downloaded $downloadedSize bytes"
    }
    finally {
        Write-Host "==> Removing scratch container $containerName"
        az storage container delete --account-name $StorageAccountName --name $containerName --auth-mode login --output none 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Failed to delete scratch container $containerName (exit $LASTEXITCODE) -- it holds the published build artifact and will need manual cleanup. It carries only a 30-minute SAS, so it stops being usable on its own shortly."
        }
    }

    Write-Host "==> Rebuilding $DeployPath from a clean slate"
    # Get-ChildItem | Remove-Item rather than Remove-Item -Path '...\*': functionally the same
    # (idempotent, recursive, safe to run against an empty or missing directory), but written this
    # way rather than as a single wildcard delete.
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
Expand-Archive -Path 'C:\Windows\Temp\mina-api-publish.zip' -DestinationPath `$target -Force
Remove-Item 'C:\Windows\Temp\mina-api-publish.zip' -Force -ErrorAction SilentlyContinue
(Get-ChildItem `$target -Recurse -File).Count
"@
    $fileCount = (Invoke-GuestPSChecked -Script $rebuildScript -TimeoutTries 60).Trim()
    Write-Host "    $fileCount files deployed"

    Write-Host "==> Ensuring app pool, site, and firewall rules match current parameters (reconciling drift)"
    # Every check below compares the EXISTING object's actual configuration to this run's
    # parameters, not just "does something with this name exist" -- a prior deploy's bindings or
    # firewall rules are recreated if they don't match, not left stale, so redeploying after
    # correcting a wrong port/address actually fixes the running host instead of silently leaving
    # the old configuration live under a same-named rule/site.
    $ensureScript = @"
`$ErrorActionPreference = 'Stop'
Import-Module WebAdministration

if (-not (Test-Path IIS:\AppPools\$AppPoolName)) { New-WebAppPool -Name '$AppPoolName' | Out-Null }
Set-ItemProperty IIS:\AppPools\$AppPoolName -Name managedRuntimeVersion -Value ''
Set-ItemProperty IIS:\AppPools\$AppPoolName -Name processModel.identityType -Value ApplicationPoolIdentity
Set-ItemProperty IIS:\AppPools\$AppPoolName -Name startMode -Value AlwaysRunning

if (-not (Get-Website -Name '$SiteName' -ErrorAction SilentlyContinue)) {
    New-Website -Name '$SiteName' -PhysicalPath '$deployPathLiteral' -ApplicationPool '$AppPoolName' ``
        -IPAddress '$AppAddress' -Port $NodePort -Force | Out-Null
} else {
    Set-ItemProperty "IIS:\Sites\$SiteName" -Name physicalPath -Value '$deployPathLiteral'
}

# Reconcile bindings: remove anything not matching the current address/ports, add what's missing.
`$desiredPorts = @($NodePort, $ManagementPort)
`$existing = @(Get-WebBinding -Name '$SiteName')
foreach (`$b in `$existing) {
    `$parts = `$b.bindingInformation -split ':'
    `$bIp = `$parts[0]; `$bPort = [int]`$parts[1]
    if (`$bIp -ne '$AppAddress' -or `$desiredPorts -notcontains `$bPort) {
        Remove-WebBinding -Name '$SiteName' -BindingInformation `$b.bindingInformation -Protocol http
    }
}
`$existing = @(Get-WebBinding -Name '$SiteName')
foreach (`$port in `$desiredPorts) {
    `$found = `$existing | Where-Object { (`$_.bindingInformation -split ':')[0] -eq '$AppAddress' -and [int](`$_.bindingInformation -split ':')[1] -eq `$port }
    if (-not `$found) {
        New-WebBinding -Name '$SiteName' -Protocol http -IPAddress '$AppAddress' -Port `$port
    }
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
Set-MinaFirewallRule 'Mina node listener (proxy only)' $NodePort '$ProxyAddress'
Set-MinaFirewallRule 'Mina management listener (corp only)' $ManagementPort '10.20.0.0/16'
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

# Only the Tokens subfolder is functionally required for the Arc/himds managed-identity token
# read -- Windows' default bypass-traverse-checking right means reaching it by exact path doesn't
# need a grant on the parent AzureConnectedMachineAgent tree too, so that broader grant is
# deliberately not made here.
Grant-MinaAcl 'C:\ProgramData\AzureConnectedMachineAgent\Tokens' '(OI)(CI)(RX)'

`$grp = 'Hybrid agent extension applications'
if (-not (Get-LocalGroupMember -Group `$grp -ErrorAction SilentlyContinue | Where-Object { `$_.Name -eq `$identity })) {
    Add-LocalGroupMember -Group `$grp -Member `$identity
}
New-Item -Path 'C:\ProgramData\Mina\dataprotection-keys' -ItemType Directory -Force | Out-Null
New-Item -Path 'C:\ProgramData\Mina\audit-exports' -ItemType Directory -Force | Out-Null
Grant-MinaAcl 'C:\ProgramData\Mina' '(OI)(CI)(M)'
Grant-MinaAcl '$deployPathLiteral' '(OI)(CI)(RX)'
'ok'
"@
    Invoke-GuestPSChecked -Script $permsScript -TimeoutTries 40 | Out-Null

    Write-Host "==> Writing environment configuration into web.config"
    # SqlConnectionString and every Mina:: value below are this script's own parameters, not
    # attacker-controlled input, but are still passed through a JSON round-trip (ConvertTo-Json /
    # ConvertFrom-Json on the guest) rather than interpolated into the script text, so a value
    # containing a quote or backtick can't break out of the generated PowerShell.
    $envVars = @{
        "ASPNETCORE_ENVIRONMENT"                    = "Production"
        "Mina__AllowDevelopmentFallbacks"            = "true"
        "Mina__Hosting__Listeners__NodePort"         = "$NodePort"
        "Mina__Hosting__Listeners__ManagementPort"   = "$ManagementPort"
        "Mina__Hosting__DataProtectionKeyPath"       = "C:\ProgramData\Mina\dataprotection-keys"
        "Mina__Hosting__ForwardedProxyCount"         = "1"
        "Mina__Audit__ExportPath"                    = "C:\ProgramData\Mina\audit-exports"
        "ConnectionStrings__MinaDb"                  = $SqlConnectionString
    }
    if ($AzureAdTenantId) { $envVars["AzureAd__TenantId"] = $AzureAdTenantId }
    if ($AzureAdClientId) {
        $envVars["AzureAd__ClientId"] = $AzureAdClientId
        # Microsoft.Identity.Web needs this set explicitly for this tenant: the Mina app
        # registration has no identifierUris (never configured during M2-1), so there is no
        # "api://..." URI for it to derive a valid audience from automatically, and without an
        # explicit Audience its computed ValidAudiences list is empty -- every real bearer token
        # is then rejected with "The audience '(null)' is invalid" regardless of how correct the
        # token itself is. Found and fixed live 2026-09-04 debugging M4-29's first-ever real
        # token round trip (the node's own managed-identity token, audience-checked against this
        # API for the first time this project has existed); Audience always equals ClientId for
        # this app's current configuration, so it is derived here rather than a separate
        # parameter that could silently drift from it.
        $envVars["AzureAd__Audience"] = $AzureAdClientId
    }
    if ($RequiredAuthContextId) { $envVars["Mina__Session__RequiredAuthContextId"] = $RequiredAuthContextId }
    # No credential accompanies this: DefaultAzureCredential on the guest finds the Arc agent's
    # managed identity, the same way the SQL connection string's Active Directory Default does.
    if ($CaKeyVaultUri) { $envVars["Mina__Pki__KeyVaultUri"] = $CaKeyVaultUri }
    # Sent via stdin (Invoke-GuestPSStdin), not interpolated into the script text, specifically so
    # a connection string or key path containing a quote or backtick can't break out of the
    # generated PowerShell -- JSON-encode here, JSON-decode on the guest.
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
    # Checked against current state rather than calling Start-* unconditionally: on a redeploy the
    # pool/site are typically already Started, and WebAdministration's Start-* cmdlets can raise an
    # error for an already-started target -- this way that's a deliberate no-op, not an error this
    # $ErrorActionPreference='Stop' block would have to tolerate or silently swallow.
    $startScript = @"
`$ErrorActionPreference = 'Stop'
Import-Module WebAdministration
if ((Get-WebAppPoolState -Name '$AppPoolName').Value -ne 'Started') { Start-WebAppPool -Name '$AppPoolName' }
if ((Get-WebsiteState -Name '$SiteName').Value -ne 'Started') { Start-Website -Name '$SiteName' }
'ok'
"@
    Invoke-GuestPSChecked -Script $startScript -TimeoutTries 40 | Out-Null

    # --- 4. Verify -------------------------------------------------------------------------------
    Write-Host "==> Waiting for the node listener to come up"
    $healthy = $false
    for ($i = 0; $i -lt 10; $i++) {
        Start-Sleep -Seconds 2
        $check = Invoke-GuestPS -Script "try { (Invoke-WebRequest -Uri 'http://${AppAddress}:${NodePort}/healthz' -UseBasicParsing -TimeoutSec 5).StatusCode } catch { 0 }"
        if ($check.'out-data'.Trim() -eq "200") { $healthy = $true; break }
    }
    if (-not $healthy) {
        throw "mina-api did not become healthy on port $NodePort within 20s -- check the site's stdout log under $DeployPath\logs."
    }
    Write-Host "mina-api is healthy on port $NodePort"

    # ADR-0006 constraint 1 in one line: a management-only endpoint must be invisible on the
    # published listener. This is the property IIS in-process hosting has to preserve for this
    # deployment shape to be safe at all -- verify it on every deploy, not just once by hand.
    Write-Host "==> Verifying listener separation (management endpoints must not be reachable on the node port)"
    $sepCheck = Invoke-GuestPS -Script @"
function Get-StatusCode(`$url) {
    try { return [int](Invoke-WebRequest -Uri `$url -UseBasicParsing -TimeoutSec 5).StatusCode }
    catch { if (`$_.Exception.Response) { return [int]`$_.Exception.Response.StatusCode }; return -1 }
}
`$node = Get-StatusCode "http://${AppAddress}:${NodePort}/api/regions"
`$mgmt = Get-StatusCode "http://${AppAddress}:${ManagementPort}/api/regions"
"`$node `$mgmt"
"@
    $parts = $sepCheck.'out-data'.Trim() -split '\s+'
    $nodeStatus, $mgmtStatus = $parts[0], $parts[1]
    if ($nodeStatus -ne "404") {
        throw "SECURITY: /api/regions (a management-only endpoint) returned $nodeStatus on the published node port $NodePort instead of 404. The management surface may be reachable from the internet. Do not consider this deployment safe."
    }
    # A connection failure (Get-StatusCode's -1) is not "the check passed" -- it means the
    # management port never responded at all, which a naive `-eq "404"` comparison would silently
    # treat as fine (-1 isn't "404" either, but the old code only checked for the 404 case and let
    # everything else through, exit 0, "confirmed"). Require an actual HTTP status.
    if ($mgmtStatus -notmatch '^\d{3}$') {
        throw "Could not reach $ManagementPort on $AppAddress at all (got '$mgmtStatus', expected an HTTP status code) -- the management listener may be down, misconfigured, or blocked by a stale firewall rule/binding from a previous deploy. This deployment is NOT verified safe or functional."
    }
    if ($mgmtStatus -eq "404") {
        throw "/api/regions returned 404 on the management port $ManagementPort too -- the app may not be routing management endpoints at all (check the app's own logs, this is a functional break, not the security check failing safe)."
    }
    Write-Host "Listener separation confirmed: node port -> 404, management port -> $mgmtStatus"
}
finally {
    Remove-Item -Path $publishDir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $zipPath -Force -ErrorAction SilentlyContinue
}

Write-Host "==> Deploy complete"
