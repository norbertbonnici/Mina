<#
.SYNOPSIS
    Installs the Mina endpoint agent, tray and research-browser integration (backlog M2-5).

.DESCRIPTION
    The install command of the Mina endpoint Intune Win32 app. Runs as SYSTEM, 64-bit, under the
    Intune Management Extension.

    Two components with different lifetimes are delivered together on purpose:

      * the agent, a Windows service running as LocalSystem, which owns the WFP containment rule
        and the loopback proxy, and
      * the tray, a per-user WPF app started at each interactive logon, which performs the WAM
        broker sign-in and launches the research browser (ARCHITECTURE 3.1, the session-0
        decision of 2026-09-05 -- a session-0 service can do neither itself).

    The security-relevant identifiers -- install root, service name, firewall rule name -- are
    constants in this script rather than fields of package.json, because this script is
    Authenticode-signed and package.json is not. Only genuinely deployment-specific values (the
    package version, the research browser's image path and the research profile directory) are
    read from the manifest.

.NOTES
    Windows PowerShell 5.1 -- this is what the Intune Management Extension runs. No ternary, no
    null-coalescing, no pipeline chain operators.

    Fails closed by design. An install that cannot confirm the research browser is present, or
    cannot confirm the service reached Running with its containment rule in force, reports failure
    rather than leaving a half-applied protected path.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Constants. Signed, therefore not overridable by a tampered manifest. -----------------------
$InstallRoot      = Join-Path $env:ProgramFiles 'Mina'
$ServiceName      = 'MinaEndpointAgent'
$ServiceDisplay   = 'Mina Endpoint Agent'
$FirewallRuleName = 'Mina-ResearchBrowser-C2-Block'
$RunValueName     = 'MinaTray'
$RunKey           = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
$ShortcutName     = 'Mina Research Browser.lnk'
$StateRoot        = Join-Path $env:ProgramData 'Mina'
$LogDir           = Join-Path $StateRoot 'Logs'
$VersionMarker    = Join-Path $StateRoot 'installed-version.json'
$AgentExeName     = 'Mina.EndpointAgent.exe'
$TrayExeName      = 'Mina.Tray.exe'

# --- Exit codes. Distinct so an Intune failure report names the actual precondition. ------------
$EXIT_OK             = 0
$EXIT_NOT_SYSTEM     = 10
$EXIT_NOT_64BIT      = 11
$EXIT_NO_BROWSER     = 12
$EXIT_BAD_PAYLOAD    = 13
$EXIT_SERVICE_FAILED = 14
$EXIT_COPY_FAILED    = 15

if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir | Out-Null }
$logFile = Join-Path $LogDir ('install-{0:yyyyMMdd-HHmmss}.log' -f (Get-Date))

function Write-Log {
    param([string] $Message, [string] $Level = 'INFO')
    $line = '{0:yyyy-MM-dd HH:mm:ss}  {1,-5}  {2}' -f (Get-Date), $Level, $Message
    Write-Host $line
    Add-Content -Path $logFile -Value $line -Encoding UTF8
}

function Stop-WithCode {
    param([string] $Message, [int] $Code)
    Write-Log $Message 'ERROR'
    Write-Log ('Install failed with exit code {0}. Log: {1}' -f $Code, $logFile) 'ERROR'
    exit $Code
}

Write-Log '================ Mina endpoint package install ================'
Write-Log ('Payload: {0}' -f $PSScriptRoot)

# --- 1. Preconditions --------------------------------------------------------------------------

# A 32-bit host resolves $env:ProgramFiles to the x86 directory and would write the service's
# ImagePath there, so this matters for correctness and not tidiness.
#
# And it is the normal case, not an edge case: the Intune Management Extension is itself a 32-bit
# process, so the install command it spawns is 32-bit too. Measured on mina-w11-01 on 2026-09-06 --
# the first real Intune-delivered install of this package failed here with exit 11, which is this
# check doing its job rather than registering a service under Program Files (x86).
#
# Re-launching into the 64-bit host is done here rather than by putting a SysNative path in the
# Intune command line, because that would depend on how Intune's own invocation expands environment
# variables and would be silently wrong if it ever stopped. This way the package is correct however
# it is started. SysNative is the WOW64 alias a 32-bit process uses to reach the real System32; it
# does not exist in a 64-bit process, which is why it is only ever reached from inside this branch.
if (-not [Environment]::Is64BitProcess) {
    $native = Join-Path $env:SystemRoot 'SysNative\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $native)) {
        Stop-WithCode ("Running 32-bit and the 64-bit PowerShell host was not found at '{0}'." -f $native) $EXIT_NOT_64BIT
    }

    # Keep the signature enforced across the re-launch where there is one to enforce. The script has
    # already satisfied whatever policy started it, so this neither weakens nor invents a check: an
    # unsigned lab build re-launches under Bypass exactly as it was started.
    $policy = 'Bypass'
    if ((Get-AuthenticodeSignature -FilePath $PSCommandPath).Status -eq 'Valid') { $policy = 'AllSigned' }

    Write-Log ('Running 32-bit (the Intune Management Extension is a 32-bit process); re-launching under {0} with -ExecutionPolicy {1}.' -f $native, $policy)
    & $native -NoProfile -ExecutionPolicy $policy -File $PSCommandPath
    $childExit = $LASTEXITCODE
    Write-Log ('The 64-bit run exited with code {0}.' -f $childExit)
    exit $childExit
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if ($identity.User.Value -ne 'S-1-5-18') {
    # Compared by SID, not by name: the account's display name is localised, its SID is not.
    Stop-WithCode ('Must run as LocalSystem (S-1-5-18); running as {0} ({1}).' -f $identity.Name, $identity.User.Value) $EXIT_NOT_SYSTEM
}
Write-Log 'Running as LocalSystem in a 64-bit host.'

$manifestPath = Join-Path $PSScriptRoot 'package.json'
if (-not (Test-Path $manifestPath)) { Stop-WithCode "Package manifest not found at $manifestPath." $EXIT_BAD_PAYLOAD }
$manifest = Get-Content -Path $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json

foreach ($field in @('packageVersion', 'researchBrowserImagePath', 'researchProfileDirectory')) {
    if ($manifest.PSObject.Properties.Name -notcontains $field) {
        Stop-WithCode "Package manifest is missing required field '$field'." $EXIT_BAD_PAYLOAD
    }
    if ([string]::IsNullOrWhiteSpace($manifest.$field)) {
        Stop-WithCode "Package manifest field '$field' is empty." $EXIT_BAD_PAYLOAD
    }
}
Write-Log ('Package version {0}, built {1}.' -f $manifest.packageVersion, $manifest.builtUtc)

$agentSource = Join-Path $PSScriptRoot 'Agent'
$traySource  = Join-Path $PSScriptRoot 'Tray'
$required = @(
    @{ Path = (Join-Path $agentSource $AgentExeName); What = 'agent' },
    @{ Path = (Join-Path $traySource  $TrayExeName);  What = 'tray'  }
)
foreach ($pair in $required) {
    if (-not (Test-Path $pair.Path)) {
        Stop-WithCode ('Payload is missing the {0} executable at {1}.' -f $pair.What, $pair.Path) $EXIT_BAD_PAYLOAD
    }
}

# The research browser must already be present. Installing the agent without it would apply a WFP
# rule to a path nothing occupies -- a rule that reads as correctly applied while containing
# nothing, which is exactly the failure mode M1-5 warned about. Edge Beta is deployed by its own
# Intune app (the first-party "Microsoft Edge version 77 and later" type, Beta channel) declared as
# a dependency of this one; if that ordering is ever lost, this is what says so out loud.
$browserPath = $manifest.researchBrowserImagePath
if (-not (Test-Path -LiteralPath $browserPath)) {
    Stop-WithCode ("Research browser not found at '{0}'. Deploy the Edge Beta app first -- it is a declared Intune dependency of this package." -f $browserPath) $EXIT_NO_BROWSER
}
Write-Log ('Research browser present at {0}.' -f $browserPath)

# --- 2. Make way for this build (upgrade path) -------------------------------------------------

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Log ('Existing service found (status {0}); stopping and removing before reinstall.' -f $existing.Status)
    if ($existing.Status -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        # Stop-Service returns before the SCM has finished. Overwriting the binary while the
        # process is still shutting down is what produces a locked-file copy failure.
        $deadline = (Get-Date).AddSeconds(30)
        while ((Get-Date) -lt $deadline) {
            $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if (-not $svc) { break }
            if ($svc.Status -eq 'Stopped') { break }
            Start-Sleep -Milliseconds 500
        }
    }
    & sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

# Trays hold their own copy of the binaries open. They belong to interactive users, so this is
# best-effort: an upgrade should not fail because somebody is logged on.
$trayProcessName = [IO.Path]::GetFileNameWithoutExtension($TrayExeName)
Get-Process -Name $trayProcessName -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Log ('Stopping running tray, pid {0}.' -f $_.Id)
    try {
        Stop-Process -Id $_.Id -Force -ErrorAction Stop
    } catch {
        Write-Log ('Could not stop tray pid {0}: {1}' -f $_.Id, $_.Exception.Message) 'WARN'
    }
}

# The service reporting Stopped, and sc.exe accepting the delete, both say nothing about whether the
# process has actually exited -- and until it has, the runtime it loaded is still mapped and its
# files cannot be replaced. That is not theoretical: the first real upgrade on mina-w11-01 failed
# here with "Access to the path 'C:\Program Files\Mina\Agent\clrjit.dll' is denied", after the
# service had already been deleted, leaving the device with no agent at all.
#
# So wait on the processes rather than on the service-control state, and identify them by the image
# path they are running from rather than by name -- an unrelated binary of the same name elsewhere
# is not ours to wait for, and the thing that matters is precisely "is anything still executing out
# of the directory I am about to overwrite".
$waitDeadline = (Get-Date).AddSeconds(60)
while ((Get-Date) -lt $waitDeadline) {
    $holders = @(Get-Process -ErrorAction SilentlyContinue | Where-Object {
        try { $_.Path -and $_.Path.StartsWith($InstallRoot, [StringComparison]::OrdinalIgnoreCase) }
        catch { $false }   # Path throws for processes this account cannot open; those are not ours.
    })
    if ($holders.Count -eq 0) { break }
    foreach ($h in $holders) { Write-Log ('Waiting for pid {0} ({1}) to exit.' -f $h.Id, $h.ProcessName) }
    Start-Sleep -Seconds 2
}
$stragglers = @(Get-Process -ErrorAction SilentlyContinue | Where-Object {
    try { $_.Path -and $_.Path.StartsWith($InstallRoot, [StringComparison]::OrdinalIgnoreCase) } catch { $false }
})
foreach ($s in $stragglers) {
    Write-Log ('Pid {0} ({1}) is still running from the install root; forcing it.' -f $s.Id, $s.ProcessName) 'WARN'
    try { Stop-Process -Id $s.Id -Force -ErrorAction Stop } catch { Write-Log ('Could not stop pid {0}: {1}' -f $s.Id, $_.Exception.Message) 'WARN' }
}
if ($stragglers.Count -gt 0) { Start-Sleep -Seconds 3 }

# --- 3. Lay down the payload -------------------------------------------------------------------

$agentTarget = Join-Path $InstallRoot 'Agent'
$trayTarget  = Join-Path $InstallRoot 'Tray'

# Retried, because waiting for the processes to exit removes the usual cause of a locked file but
# not every cause: an antimalware scan or the indexer can hold a handle open for a moment after the
# owning process has gone. The failure this guards is not a slow install, it is a half-installed
# one -- by this point the old service is already deleted, so giving up here leaves the device with
# no agent and the containment rule still in force.
$copied = $false
$copyError = ''
for ($attempt = 1; $attempt -le 5 -and -not $copied; $attempt++) {
    try {
        foreach ($dir in @($InstallRoot, $agentTarget, $trayTarget)) {
            if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
        }
        # Clear rather than merge: an assembly left behind by a previous build is a stale binary
        # sitting next to signed ones, waiting to be loaded.
        Get-ChildItem -Path $agentTarget -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
        Get-ChildItem -Path $trayTarget  -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force

        Copy-Item -Path (Join-Path $agentSource '*') -Destination $agentTarget -Recurse -Force
        Copy-Item -Path (Join-Path $traySource  '*') -Destination $trayTarget  -Recurse -Force
        $copied = $true
        Write-Log ('Payload copied to {0}{1}.' -f $InstallRoot, $(if ($attempt -gt 1) { " on attempt $attempt" } else { '' }))
    } catch {
        $copyError = $_.Exception.Message
        if ($attempt -lt 5) {
            Write-Log ('Copy attempt {0} failed ({1}); retrying in {2}s.' -f $attempt, $copyError, (2 * $attempt)) 'WARN'
            Start-Sleep -Seconds (2 * $attempt)
        }
    }
}
if (-not $copied) {
    Stop-WithCode ('Failed to copy payload after 5 attempts: {0}' -f $copyError) $EXIT_COPY_FAILED
}

# --- 4. Research profile directory, with an ACL ------------------------------------------------

# Machine-wide by decision (2026-09-05): WindowsPeerAuthorizer matches --user-data-dir as one exact
# literal string with no environment expansion on either side, so the path must resolve identically
# for every user on the machine. The ACL below keeps service accounts, network logons and non-
# interactive callers out; it does NOT separate two interactive users from each other, which is the
# accepted trade of the machine-wide choice. See packaging/README.md.
$profileDir = $manifest.researchProfileDirectory
if (-not (Test-Path -LiteralPath $profileDir)) {
    New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
    Write-Log ('Created research profile directory {0}.' -f $profileDir)
}

try {
    $acl = Get-Acl -LiteralPath $profileDir
    $acl.SetAccessRuleProtection($true, $false)   # break inheritance, drop the inherited ACEs
    foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRule($rule) }

    # Well-known SIDs, so this is correct on a non-English Windows too.
    $grants = @(
        @{ Sid = 'S-1-5-18';     Rights = 'FullControl' },  # LocalSystem
        @{ Sid = 'S-1-5-32-544'; Rights = 'FullControl' },  # BUILTIN\Administrators
        @{ Sid = 'S-1-5-4';      Rights = 'Modify'      }   # NT AUTHORITY\INTERACTIVE
    )
    foreach ($g in $grants) {
        $account = New-Object Security.Principal.SecurityIdentifier($g.Sid)
        $ace = New-Object Security.AccessControl.FileSystemAccessRule(
            $account, $g.Rights, 'ContainerInherit, ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($ace)
    }
    Set-Acl -LiteralPath $profileDir -AclObject $acl
    Write-Log 'Research profile ACL set: SYSTEM and Administrators full, INTERACTIVE modify, inheritance broken.'
} catch {
    # Not fatal. The profile is a browser data directory, not a control -- containment is the WFP
    # rule and the proxy peer check, and neither depends on this ACL.
    Write-Log ('Could not set research profile ACL: {0}' -f $_.Exception.Message) 'WARN'
}

# --- 5. Service --------------------------------------------------------------------------------

$agentExe = Join-Path $agentTarget $AgentExeName
try {
    New-Service -Name $ServiceName `
                -BinaryPathName ('"{0}"' -f $agentExe) `
                -DisplayName $ServiceDisplay `
                -Description 'Establishes and maintains the Mina protected research-egress path, and enforces research-browser network containment (ADR-0001 variant C2).' `
                -StartupType Automatic | Out-Null

    # A containment agent that dies must come back. Without this the WFP rule stays applied while
    # nothing renews the session: browsing fails closed, which is safe but silently unusable.
    & sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null
    Write-Log 'Service created with automatic start and restart-on-failure actions.'
} catch {
    Stop-WithCode ('Failed to create service: {0}' -f $_.Exception.Message) $EXIT_SERVICE_FAILED
}

try {
    Start-Service -Name $ServiceName
} catch {
    Stop-WithCode ("Service '{0}' did not start: {1}. The agent refuses to start unless it can confirm the containment rule is in place -- check the Windows event log and {2}." -f $ServiceName, $_.Exception.Message, $LogDir) $EXIT_SERVICE_FAILED
}

$deadline = (Get-Date).AddSeconds(60)
$running = $false
while ((Get-Date) -lt $deadline) {
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') { $running = $true; break }
    Start-Sleep -Milliseconds 500
}
if (-not $running) {
    Stop-WithCode "Service '$ServiceName' did not reach Running within 60s." $EXIT_SERVICE_FAILED
}
Write-Log 'Service is running.'

# The agent applies the containment rule before it serves anything, so by the time the service is
# Running the rule must exist. Checking it here turns "the service started" into "the control is
# actually in force" -- which is the property this package exists to deliver, and the only one
# worth reporting success on.
$rule = Get-NetFirewallRule -Name $FirewallRuleName -ErrorAction SilentlyContinue
if (-not $rule) {
    Stop-WithCode ("Service is running but the containment rule '{0}' is absent. Refusing to report a protected path that is not enforced." -f $FirewallRuleName) $EXIT_SERVICE_FAILED
}
$ruleProgram = ($rule | Get-NetFirewallApplicationFilter).Program
Write-Log ("Containment rule '{0}' present, scoped to '{1}'." -f $FirewallRuleName, $ruleProgram)
if ($ruleProgram -ne $browserPath) {
    Write-Log ("Containment rule names '{0}' but the manifest configures '{1}'." -f $ruleProgram, $browserPath) 'WARN'
}

# --- 6. Tray autostart and shortcut ------------------------------------------------------------

$trayExe = Join-Path $trayTarget $TrayExeName

# HKLM Run, so the tray starts for every interactive user without a per-user install. The tray
# holds a Local\Mina.Tray mutex, so a second launch (from the shortcut) exits rather than stacking
# a second notification-area icon.
Set-ItemProperty -Path $RunKey -Name $RunValueName -Value ('"{0}"' -f $trayExe) -Type String
Write-Log ('Tray registered for autostart at {0}\{1}.' -f $RunKey, $RunValueName)

$startMenu = [Environment]::GetFolderPath('CommonPrograms')
$shortcutPath = Join-Path $startMenu $ShortcutName
try {
    $shell = New-Object -ComObject WScript.Shell
    $lnk = $shell.CreateShortcut($shortcutPath)
    # Targets the TRAY, not the browser. The agent's proxy binds an ephemeral port, so only the
    # tray knows where to point --proxy-server; a shortcut launching Edge directly is option (c)
    # of the ARCHITECTURE 3.1 decision, rejected precisely because it reintroduces a fixed,
    # predictable port.
    $lnk.TargetPath       = $trayExe
    $lnk.WorkingDirectory = $trayTarget
    $lnk.IconLocation     = ('{0},0' -f $trayExe)
    $lnk.Description      = 'Open the Mina research browser through the protected egress path'
    $lnk.Save()
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($shell)
    Write-Log ('Start-menu shortcut written to {0}.' -f $shortcutPath)
} catch {
    Write-Log ('Could not create Start-menu shortcut: {0}' -f $_.Exception.Message) 'WARN'
}

# --- 7. Detection marker -----------------------------------------------------------------------

$marker = [ordered]@{
    packageVersion           = $manifest.packageVersion
    installedUtc             = (Get-Date).ToUniversalTime().ToString('o')
    installRoot              = $InstallRoot
    serviceName              = $ServiceName
    researchBrowserImagePath = $browserPath
    researchProfileDirectory = $profileDir
}
$marker | ConvertTo-Json -Depth 4 | Set-Content -Path $VersionMarker -Encoding UTF8
Write-Log ('Detection marker written to {0}.' -f $VersionMarker)

Write-Log ('Install completed successfully (version {0}).' -f $manifest.packageVersion)
exit $EXIT_OK
