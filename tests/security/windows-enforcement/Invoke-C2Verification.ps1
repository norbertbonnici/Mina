#Requires -RunAsAdministrator
<#
.SYNOPSIS
    ADR-0001 M1-5 verification register, item 1: per-app network controls key on the image path.

.DESCRIPTION
    Tests the constraint the whole C2 enforcement variant rests on. ADR-0001 constraint 1 asserts
    that Windows per-app network controls identify an application by its executable image path
    only. If that holds, two profiles of one Edge installation cannot be told apart, while two
    installations at different paths can -- which is precisely why variant C2 (distinct research
    browser binary) was chosen over C1 (stable Edge, separate --user-data-dir).

    Four cases, run against two real Edge installations:

      1 baseline  Stable / profile A, no rule       expect Tx > 0  the method detects egress
      2 blocked   Stable / profile A, rule on path  expect Tx = 0  the rule bites
      3 blocked   Stable / profile B, rule on path  expect Tx = 0  a different profile of the
                                                                   same binary is caught anyway
      4 untouched Beta   / profile C, rule on path  expect Tx > 0  a different image path is
                                                                   unaffected

    Case 3 failing (Tx > 0) would mean profiles ARE separable and C1 was viable after all.
    Case 4 failing (Tx = 0) would mean path targeting is not precise and C2 cannot be built.

.NOTES
    Observation is at the NIC, via pktmon counters -- not in the browser and not at a server.
    The target is a port nothing listens on, on a host off this machine, so the only thing that
    can put packets on the wire toward it is the browser under test. A blocked process emits
    zero; an unblocked one emits SYNs regardless of there being no listener, which is all this
    needs to measure.

    An on-box target CANNOT be used. Windows treats traffic to the host's own address as
    loopback and exempts it from outbound filtering, so a canary listening on this machine is
    reached even by a process that is comprehensively blocked -- every case passes and the test
    lies. Established empirically here on 2026-09-04, and it applies equally to the M1-6 leak
    suites: point them off-box or they prove nothing.

    This uses Windows Firewall rules rather than the WFP API directly. Both key on the image
    path (the firewall is a WFP consumer), so this evidences the constraint. The shipping agent
    installs WFP filters directly instead, for tamper resistance against a local administrator
    -- that is a property of the enforcement, not of the identification behaviour tested here.

    The rule created is named MINA-C2-VERIFY-<runid> and is removed in a finally block. While
    cases 2-4 run, Edge Stable on this machine has no outbound network access -- roughly a
    minute.
#>
[CmdletBinding()]
param(
    # Off-box address the browser is pointed at. Nothing needs to listen on it.
    [Parameter()] [string] $TargetIp = '10.20.40.21',
    [Parameter()] [int]    $TargetPort = 18099,
    [Parameter()] [string] $StablePath = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
    [Parameter()] [string] $BetaPath   = 'C:\Program Files (x86)\Microsoft\Edge Beta\Application\msedge.exe',
    # Seconds each case is given to generate traffic before the browser is killed.
    [Parameter()] [int]    $DwellSeconds = 12
)

$ErrorActionPreference = 'Stop'

foreach ($exe in @($StablePath, $BetaPath)) {
    if (-not (Test-Path -LiteralPath $exe)) {
        throw "Edge installation not found at '$exe'. Variant C2 needs two channels installed at distinct image paths."
    }
}
if ((Get-Item -LiteralPath $StablePath).FullName -eq (Get-Item -LiteralPath $BetaPath).FullName) {
    throw 'StablePath and BetaPath resolve to the same image. The whole point of the test is two distinct paths.'
}

$runId    = [guid]::NewGuid().ToString('N').Substring(0, 8)
$ruleName = "MINA-C2-VERIFY-$runId"
$spawned  = New-Object System.Collections.ArrayList
$dirs     = New-Object System.Collections.ArrayList

# Native tools here (taskkill, pktmon) write to stderr for benign conditions such as an
# already-dead pid or a stopped capture. Under $ErrorActionPreference='Stop' PowerShell 5.1
# promotes that to a terminating NativeCommandError, so those calls run through here.
function Invoke-Quietly {
    param([Parameter(Mandatory)] [scriptblock] $Block)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $Block 2>$null } catch { } finally { $ErrorActionPreference = $prev }
}

function Stop-ProcessTree {
    param([Parameter(Mandatory)] [int] $ProcessId)
    Invoke-Quietly { & taskkill.exe /PID $ProcessId /T /F | Out-Null }
}

function Get-TxPacketCount {
    $text = (Invoke-Quietly { & pktmon.exe counters } | Out-String)
    $max = 0
    foreach ($m in [regex]::Matches($text, '\|\s*Tx\s+(\d+)\s+(\d+)')) {
        $n = [int]$m.Groups[1].Value
        if ($n -gt $max) { $max = $n }
    }
    return $max
}

function Measure-BrowserEgress {
    param(
        [Parameter(Mandatory)] [string] $Exe,
        [Parameter(Mandatory)] [string] $Tag
    )
    Invoke-Quietly { & pktmon.exe stop | Out-Null }
    Invoke-Quietly { & pktmon.exe filter remove | Out-Null }
    Invoke-Quietly { & pktmon.exe filter add MinaC2 -i $TargetIp -p $TargetPort | Out-Null }
    Invoke-Quietly { & pktmon.exe start --capture --counters-only | Out-Null }

    $dir = Join-Path $env:TEMP "mina-c2-$runId-$Tag"
    [void]$dirs.Add($dir)
    $proc = Start-Process -FilePath $Exe -WindowStyle Hidden -PassThru -ArgumentList @(
        '--headless=new'
        "--user-data-dir=$dir"
        '--no-first-run'
        '--no-default-browser-check'
        '--disable-gpu'
        "http://${TargetIp}:${TargetPort}/$Tag"
    )
    [void]$spawned.Add($proc.Id)
    Start-Sleep -Seconds $DwellSeconds
    Stop-ProcessTree $proc.Id
    Invoke-Quietly { & pktmon.exe stop | Out-Null }
    return Get-TxPacketCount
}

$cases = [ordered]@{}
try {
    $cases['1 baseline  Stable/A (no rule)']         = Measure-BrowserEgress -Exe $StablePath -Tag 'A'

    New-NetFirewallRule -DisplayName $ruleName -Name $ruleName -Direction Outbound `
        -Action Block -Program $StablePath -Profile Any -Enabled True | Out-Null

    $cases['2 blocked   Stable/A (rule on Stable)']  = Measure-BrowserEgress -Exe $StablePath -Tag 'A2'
    $cases['3 blocked   Stable/B (rule on Stable)']  = Measure-BrowserEgress -Exe $StablePath -Tag 'B'
    $cases['4 untouched Beta/C   (rule on Stable)']  = Measure-BrowserEgress -Exe $BetaPath   -Tag 'C'
}
finally {
    Invoke-Quietly { Remove-NetFirewallRule -Name $ruleName | Out-Null }
    Invoke-Quietly { & pktmon.exe stop | Out-Null }
    Invoke-Quietly { & pktmon.exe filter remove | Out-Null }
    foreach ($procId in ($spawned | Select-Object -Unique)) { Stop-ProcessTree $procId }
    foreach ($d in $dirs) { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
}

$ruleGone    = -not [bool](Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue)
$filtersGone = (Invoke-Quietly { & pktmon.exe filter list } | Out-String) -notmatch 'MinaC2'

$baseline  = $cases['1 baseline  Stable/A (no rule)']
$sameA     = $cases['2 blocked   Stable/A (rule on Stable)']
$otherProf = $cases['3 blocked   Stable/B (rule on Stable)']
$otherPath = $cases['4 untouched Beta/C   (rule on Stable)']

# Fail closed: an inconclusive baseline is a broken measurement, not a passing test.
$verdict =
    if ($baseline -le 0) { 'INCONCLUSIVE - baseline produced no egress; the measurement is broken, not the claim' }
    elseif ($sameA -eq 0 -and $otherProf -eq 0 -and $otherPath -gt 0) { 'CONSTRAINT 1 CONFIRMED - profiles inseparable, image paths separable' }
    elseif ($otherProf -gt 0) { 'CONSTRAINT 1 REFUTED - a second profile of the same binary escaped the rule; C1 may be viable' }
    elseif ($otherPath -eq 0) { 'CONSTRAINT 1 REFUTED - a different image path was also blocked; path targeting is not precise' }
    else { 'UNEXPECTED - review the per-case counts' }

[pscustomobject]@{
    RunId          = $runId
    Target         = "${TargetIp}:${TargetPort}"
    StableVersion  = (Get-Item -LiteralPath $StablePath).VersionInfo.ProductVersion
    BetaVersion    = (Get-Item -LiteralPath $BetaPath).VersionInfo.ProductVersion
    Cases          = $cases
    RuleRemoved    = $ruleGone
    FiltersCleared = $filtersGone
    Verdict        = $verdict
}
