<#
.SYNOPSIS
    Intune detection script for the Mina endpoint package (backlog M2-5).

.DESCRIPTION
    Intune's contract for a custom detection script: exit 0 AND write something to stdout means
    "installed"; anything else means "not installed", and Intune will (re)run the install command.

    This checks four things, and the fourth is a deliberate design choice rather than a completeness
    reflex:

      1  the detection marker exists and names exactly the version this package carries,
      2  the agent service is registered,
      3  the tray executable is present,
      4  the containment firewall rule is present.

    Including (4) makes Intune's own compliance cycle the remediation path for a deleted
    containment rule. That matters more than it first looks: if the rule is gone, the research
    browser is not merely unprotected, it is *unblocked* -- it reaches the internet through ordinary
    corporate egress, which is precisely the leak ADR-0001 variant C2 exists to prevent, and it does
    so silently. Reporting "not installed" makes Intune reinstall, which restarts the agent, which
    reapplies the rule before it serves anything.

    The honest limit: Intune evaluates on its own cadence (typically every few hours, and at
    check-in after a reboot), so this is periodic remediation, not the continuous re-checking that
    backlog M2-4 still lists as outstanding. It narrows that gap; it does not close it.

.NOTES
    Windows PowerShell 5.1. Any unexpected failure must read as "not installed" rather than as an
    error, so the whole body runs inside one try/catch -- a detection script that throws is a
    detection script whose result Intune cannot use.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Substituted by Build-MinaEndpointPackage.ps1 before signing, so the expected version lives in
# signed code rather than being read back from the unsigned manifest this package also carries.
$ExpectedVersion  = '@@PACKAGE_VERSION@@'

$ServiceName      = 'MinaEndpointAgent'
$FirewallRuleName = 'Mina-ResearchBrowser-C2-Block'
$VersionMarker    = Join-Path (Join-Path $env:ProgramData 'Mina') 'installed-version.json'
# ProgramW6432 rather than ProgramFiles: it names the 64-bit Program Files from either bitness,
# while ProgramFiles resolves to the x86 directory in a 32-bit host. The app declares this rule as
# 64-bit so it should not arise -- but if it ever did, this script would find no tray, report "not
# installed" on a machine that is, and put Intune into a permanent reinstall loop. One variable
# removes the whole failure mode. (Install.ps1 needs a real re-launch instead, because it also
# writes to HKLM, where a 32-bit process is redirected into Wow6432Node.)
$programFiles     = if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles }
$TrayExe          = Join-Path (Join-Path (Join-Path $programFiles 'Mina') 'Tray') 'Mina.Tray.exe'

try {
    if (-not (Test-Path -LiteralPath $VersionMarker)) { exit 1 }

    $marker = Get-Content -LiteralPath $VersionMarker -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($marker.PSObject.Properties.Name -notcontains 'packageVersion') { exit 1 }
    if ($marker.packageVersion -ne $ExpectedVersion) { exit 1 }

    if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) { exit 1 }
    if (-not (Test-Path -LiteralPath $TrayExe)) { exit 1 }
    if (-not (Get-NetFirewallRule -Name $FirewallRuleName -ErrorAction SilentlyContinue)) { exit 1 }

    Write-Output ("Mina endpoint package {0} detected." -f $ExpectedVersion)
    exit 0
} catch {
    exit 1
}
