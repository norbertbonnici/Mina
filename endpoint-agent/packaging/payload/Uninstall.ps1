<#
.SYNOPSIS
    Removes the Mina endpoint agent, tray and research-browser integration (backlog M2-5).

.DESCRIPTION
    The uninstall command of the Mina endpoint Intune Win32 app. Runs as SYSTEM, 64-bit.

    The order matters, and one step in it is load-bearing rather than tidy: the containment
    firewall rule must be removed.

    The agent applies an outbound-block rule scoped to the research browser's image path, and that
    rule is deliberately persistent -- it exists whenever the agent is installed, not only while a
    session is live, because M1-5 register item 4 measured twelve third-party endpoints escaping
    through a two-second gap between browser start and rule application. Persistence is the right
    design, but it means the rule outlives the process that created it. Removing the agent while
    leaving the rule behind would leave the research browser permanently unable to reach anything,
    with nothing left on the machine to explain why or to proxy it -- fail-closed turned into
    fail-forever. Nothing else on the endpoint would clean it up.

    Deliberately NOT removed: the research profile directory. It holds the analyst's research
    browsing data, and destroying it on uninstall is a decision with governance consequences in
    both directions -- see packaging/README.md, "What uninstall leaves behind". Its location is
    logged prominently so an operator can act on it deliberately.

.NOTES
    Windows PowerShell 5.1. Best-effort throughout: an uninstall that aborts halfway leaves a
    machine in a worse state than one that continues and reports what it could not do. The single
    exception is the firewall rule, whose removal is verified and reported as a failure if it
    could not be confirmed.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$InstallRoot      = Join-Path $env:ProgramFiles 'Mina'
$ServiceName      = 'MinaEndpointAgent'
$FirewallRuleName = 'Mina-ResearchBrowser-C2-Block'
$RunValueName     = 'MinaTray'
$RunKey           = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
$ShortcutName     = 'Mina Research Browser.lnk'
$StateRoot        = Join-Path $env:ProgramData 'Mina'
$LogDir           = Join-Path $StateRoot 'Logs'
$VersionMarker    = Join-Path $StateRoot 'installed-version.json'
$TrayExeName      = 'Mina.Tray.exe'

$EXIT_OK           = 0
$EXIT_NOT_64BIT    = 11
$EXIT_RULE_REMAINS = 20

if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
$logFile = Join-Path $LogDir ('uninstall-{0:yyyyMMdd-HHmmss}.log' -f (Get-Date))

function Write-Log {
    param([string] $Message, [string] $Level = 'INFO')
    $line = '{0:yyyy-MM-dd HH:mm:ss}  {1,-5}  {2}' -f (Get-Date), $Level, $Message
    Write-Host $line
    Add-Content -Path $logFile -Value $line -Encoding UTF8
}

Write-Log '================ Mina endpoint package uninstall ================'

# The same 32-bit re-launch Install.ps1 does, and for a sharper reason: the Intune Management
# Extension is a 32-bit process, so an uninstall left running 32-bit resolves $env:ProgramFiles to
# the x86 directory, finds none of what it is meant to remove, and reports success having removed
# nothing -- leaving the containment rule in place with no agent, which is the fail-forever state
# this script exists to prevent.
if (-not [Environment]::Is64BitProcess) {
    $native = Join-Path $env:SystemRoot 'SysNative\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $native)) {
        Write-Log ("Running 32-bit and the 64-bit PowerShell host was not found at '{0}'. Refusing to continue rather than report a removal that did nothing." -f $native) 'ERROR'
        exit $EXIT_NOT_64BIT
    }
    $policy = 'Bypass'
    if ((Get-AuthenticodeSignature -FilePath $PSCommandPath).Status -eq 'Valid') { $policy = 'AllSigned' }
    Write-Log ('Running 32-bit; re-launching under {0} with -ExecutionPolicy {1}.' -f $native, $policy)
    & $native -NoProfile -ExecutionPolicy $policy -File $PSCommandPath
    $childExit = $LASTEXITCODE
    Write-Log ('The 64-bit run exited with code {0}.' -f $childExit)
    exit $childExit
}

# Record what we are about to remove, before removing it -- the marker is the only on-disk record
# of which build this machine was carrying.
if (Test-Path $VersionMarker) {
    try {
        $marker = Get-Content -Path $VersionMarker -Raw -Encoding UTF8 | ConvertFrom-Json
        Write-Log ('Removing package version {0}, installed {1}.' -f $marker.packageVersion, $marker.installedUtc)
    } catch {
        Write-Log ('Detection marker present but unreadable: {0}' -f $_.Exception.Message) 'WARN'
    }
}

# --- 1. Service ---------------------------------------------------------------------------------

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -ne 'Stopped') {
        Write-Log ('Stopping service {0} (status {1}).' -f $ServiceName, $svc.Status)
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        $deadline = (Get-Date).AddSeconds(30)
        while ((Get-Date) -lt $deadline) {
            $s = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if (-not $s) { break }
            if ($s.Status -eq 'Stopped') { break }
            Start-Sleep -Milliseconds 500
        }
    }
    & sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Write-Log ('Service {0} still present after delete; a reboot will complete its removal.' -f $ServiceName) 'WARN'
    } else {
        Write-Log ('Service {0} removed.' -f $ServiceName)
    }
} else {
    Write-Log ('Service {0} was not present.' -f $ServiceName)
}

# --- 2. Containment rule. The one step that is not best-effort. ---------------------------------

$rule = Get-NetFirewallRule -Name $FirewallRuleName -ErrorAction SilentlyContinue
if ($rule) {
    Write-Log ("Removing containment rule '{0}'." -f $FirewallRuleName)
    Remove-NetFirewallRule -Name $FirewallRuleName -ErrorAction SilentlyContinue
} else {
    Write-Log ("Containment rule '{0}' was not present." -f $FirewallRuleName)
}

# Verified rather than assumed: leaving this rule behind blocks the research browser permanently
# with nothing left on the machine to explain it.
$ruleRemains = $null -ne (Get-NetFirewallRule -Name $FirewallRuleName -ErrorAction SilentlyContinue)

# --- 3. Tray, autostart, shortcut ---------------------------------------------------------------

$trayProcessName = [IO.Path]::GetFileNameWithoutExtension($TrayExeName)
Get-Process -Name $trayProcessName -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Log ('Stopping running tray, pid {0}.' -f $_.Id)
    Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
}

if (Get-ItemProperty -Path $RunKey -Name $RunValueName -ErrorAction SilentlyContinue) {
    Remove-ItemProperty -Path $RunKey -Name $RunValueName -ErrorAction SilentlyContinue
    Write-Log ('Removed tray autostart value {0}\{1}.' -f $RunKey, $RunValueName)
}

$shortcutPath = Join-Path ([Environment]::GetFolderPath('CommonPrograms')) $ShortcutName
if (Test-Path -LiteralPath $shortcutPath) {
    Remove-Item -LiteralPath $shortcutPath -Force -ErrorAction SilentlyContinue
    Write-Log ('Removed Start-menu shortcut {0}.' -f $shortcutPath)
}

# --- 4. Program files ---------------------------------------------------------------------------

if (Test-Path -LiteralPath $InstallRoot) {
    try {
        Remove-Item -LiteralPath $InstallRoot -Recurse -Force -ErrorAction Stop
        Write-Log ('Removed {0}.' -f $InstallRoot)
    } catch {
        # Usually a file still mapped by a process that has not fully exited. Say so rather than
        # failing the uninstall: the controls are already gone by this point.
        Write-Log ('Could not fully remove {0}: {1}' -f $InstallRoot, $_.Exception.Message) 'WARN'
    }
}

if (Test-Path -LiteralPath $VersionMarker) {
    Remove-Item -LiteralPath $VersionMarker -Force -ErrorAction SilentlyContinue
    Write-Log 'Removed detection marker.'
}

# --- 5. What is deliberately left behind --------------------------------------------------------

$profileDir = Join-Path $StateRoot 'ResearchProfile'
if (Test-Path -LiteralPath $profileDir) {
    Write-Log ('LEFT IN PLACE: research profile data at {0}. This holds research browsing data and is not removed automatically -- remove it deliberately if the machine is being reassigned or decommissioned.' -f $profileDir) 'WARN'
}
Write-Log ('LEFT IN PLACE: install and uninstall logs under {0}.' -f $LogDir)

if ($ruleRemains) {
    Write-Log ("Containment rule '{0}' could NOT be removed. The research browser will remain blocked on this machine until it is removed by hand: Remove-NetFirewallRule -Name '{0}'" -f $FirewallRuleName) 'ERROR'
    exit $EXIT_RULE_REMAINS
}

Write-Log 'Uninstall completed.'
exit $EXIT_OK
