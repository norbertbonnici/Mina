#Requires -RunAsAdministrator
<#
.SYNOPSIS
    ADR-0001 M1-5 verification register, item 4: no pre-proxy traffic at browser startup under
    C2, with enforcement in place before the browser is spawned.

.DESCRIPTION
    A browser emits traffic of its own accord at startup -- connectivity probes, update and
    telemetry endpoints, new-tab content, prefetch and preconnect -- before any page the analyst
    asked for. Under variant C2 none of it may leave, because the research browser's only
    permitted route out is loopback to the agent's proxy (THREAT_MODEL N11/N12).

    The substance of the claim is an ordering one. C2's rules are installed by the agent and
    persist whenever the agent is installed, so the property to establish is that there is no
    window at spawn in which packets escape before filters apply. Three cases:

      1 no rule                  expect egress > 0   the browser really does reach out at
                                                     startup, so the control is not vacuous
      2 rule up BEFORE spawn     expect egress = 0   nothing escapes, which is the claim
      3 rule applied AFTER spawn expect egress > 0   the ordering requirement is real, not
                                                     ceremony -- this is the negative control

    Case 3 is what makes case 2 worth anything. A rule that is only ever installed first proves
    nothing about whether installing it first matters.

.NOTES
    Two independent observations, because neither alone is sufficient here:

    * pktmon counters toward one off-box address, which the browser is pointed at as its startup
      URL. Precise, but only sees that one destination.
    * Per-process TCP connections owned by the research browser to any non-loopback address.
      This catches the browser's own chatter to destinations this script never nominated, which
      is the actual N11/N12 concern. Attribution is by image path rather than PID tree: the
      research browser is Edge Beta, ordinary browsing on this machine is Edge Stable, so
      connections are matched by the owning process's path. That avoids Win32_Process command
      line lookups, which are unreliable inside a script on this host.

    Enforcement is a Windows Firewall rule scoped to the research browser's image path. Note
    that Windows does not filter loopback, so "block all outbound for this image" already leaves
    the loopback-to-agent-proxy path open and C2's allow rule is implicit here. Filters the agent
    adds directly through the WFP API are not automatically so forgiving -- an ALE filter can
    block loopback -- so the agent's own rule set must permit that path explicitly rather than
    inheriting this behaviour. That is an M2-4 concern, flagged here because this test cannot
    surface it.

    Headless is used so this stays scriptable and does not put windows on the operator's desktop.
    Headless Chromium suppresses some background services, so case 1 likely UNDER-reports what a
    headed research browser would emit. That weakens case 1 as a measure of how much a browser
    leaks; it does not weaken case 2, which is a claim that a block holds from t=0, nor case 3.
    The observed endpoints are reported so the reader can see what was actually emitted.

    Only the research browser (Edge Beta) is ever blocked. Ordinary Edge Stable browsing on this
    machine is untouched throughout.
#>
[CmdletBinding()]
param(
    [Parameter()] [string] $TargetIp    = '10.20.40.21',
    [Parameter()] [int]    $TargetPort  = 18099,
    # The research browser under C2: a distinct image path from ordinary Edge.
    [Parameter()] [string] $ResearchBrowserPath = 'C:\Program Files (x86)\Microsoft\Edge Beta\Application\msedge.exe',
    [Parameter()] [int]    $DwellSeconds = 12,
    # How long the browser is allowed to run unfiltered in case 3 before the rule lands.
    [Parameter()] [int]    $PostSpawnDelaySeconds = 2
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'MinaEnforcementProbe.psm1') -Force

if (-not (Test-Path -LiteralPath $ResearchBrowserPath)) {
    throw "Research browser not found at '$ResearchBrowserPath'."
}

$runId    = [guid]::NewGuid().ToString('N').Substring(0, 8)
$ruleName = "MINA-C2-STARTUP-$runId"

function Get-ResearchBrowserEndpoints {
    <#
        Distinct non-loopback remote endpoints currently owned by any process running the
        research browser image. Loopback is excluded deliberately: under C2 that is the
        permitted path to the agent's proxy, not a leak.
    #>
    $pids = @(Get-Process -Name 'msedge' -ErrorAction SilentlyContinue |
              Where-Object { $_.Path -eq $ResearchBrowserPath } |
              Select-Object -ExpandProperty Id)
    if ($pids.Count -eq 0) { return @() }

    $conns = Get-NetTCPConnection -ErrorAction SilentlyContinue |
             Where-Object {
                 $pids -contains $_.OwningProcess -and
                 $_.RemoteAddress -notmatch '^(127\.|::1$|0\.0\.0\.0$)' -and
                 $_.RemotePort -ne 0
             }
    return @($conns | ForEach-Object { '{0}:{1}' -f $_.RemoteAddress, $_.RemotePort } | Sort-Object -Unique)
}

function Invoke-StartupCase {
    param(
        [ValidateSet('none', 'before', 'after')] [string] $RuleTiming,
        [string] $Tag
    )

    Invoke-Quietly { Remove-NetFirewallRule -Name $ruleName | Out-Null }

    if ($RuleTiming -eq 'before') {
        New-NetFirewallRule -DisplayName $ruleName -Name $ruleName -Direction Outbound `
            -Action Block -Program $ResearchBrowserPath -Profile Any -Enabled True | Out-Null
    }

    Invoke-Quietly { & pktmon.exe stop | Out-Null }
    Invoke-Quietly { & pktmon.exe filter remove | Out-Null }
    Invoke-Quietly { & pktmon.exe filter add MinaProbe -i $TargetIp -p $TargetPort | Out-Null }
    Invoke-Quietly { & pktmon.exe start --capture --counters-only | Out-Null }

    $dir  = Join-Path $env:TEMP "mina-startup-$runId-$Tag"
    $seen = New-Object System.Collections.ArrayList
    $proc = Start-Process -FilePath $ResearchBrowserPath -WindowStyle Hidden -PassThru -ArgumentList @(
        '--headless=new'
        "--user-data-dir=$dir"
        '--no-first-run'
        '--no-default-browser-check'
        '--disable-gpu'
        "http://${TargetIp}:${TargetPort}/$Tag"
    )

    try {
        if ($RuleTiming -eq 'after') {
            Start-Sleep -Seconds $PostSpawnDelaySeconds
            New-NetFirewallRule -DisplayName $ruleName -Name $ruleName -Direction Outbound `
                -Action Block -Program $ResearchBrowserPath -Profile Any -Enabled True | Out-Null
        }

        $deadline = (Get-Date).AddSeconds($DwellSeconds)
        while ((Get-Date) -lt $deadline) {
            foreach ($e in (Get-ResearchBrowserEndpoints)) {
                if (-not $seen.Contains($e)) { [void]$seen.Add($e) }
            }
            Start-Sleep -Milliseconds 250
        }
    }
    finally {
        Stop-ProcessTree $proc.Id
        Invoke-Quietly { & pktmon.exe stop | Out-Null }
        Invoke-Quietly { Remove-NetFirewallRule -Name $ruleName | Out-Null }
        Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
    }

    return [pscustomobject]@{
        Tx        = Get-TxPacketCount
        Endpoints = @($seen)
    }
}

$results = [ordered]@{}
try {
    $results['1 no rule']                 = Invoke-StartupCase -RuleTiming 'none'   -Tag 'norule'
    $results['2 rule BEFORE spawn']       = Invoke-StartupCase -RuleTiming 'before' -Tag 'before'
    $results['3 rule AFTER spawn']        = Invoke-StartupCase -RuleTiming 'after'  -Tag 'after'
}
finally {
    Invoke-Quietly { Remove-NetFirewallRule -Name $ruleName | Out-Null }
    $filtersCleared = Clear-ProbeCapture
}

$ruleGone = -not [bool](Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue)

$none   = $results['1 no rule']
$before = $results['2 rule BEFORE spawn']
$after  = $results['3 rule AFTER spawn']

$beforeSilent = ($before.Tx -eq 0 -and $before.Endpoints.Count -eq 0)

$verdict =
    if ($none.Tx -le 0) {
        'INCONCLUSIVE - the unfiltered browser produced no egress even to its own startup URL; the measurement is broken'
    }
    elseif ($beforeSilent -and $after.Tx -gt 0) {
        'ITEM 4 CONFIRMED - nothing escaped when enforcement preceded spawn, and traffic did escape when it did not; the ordering requirement is real'
    }
    elseif ($beforeSilent -and $after.Tx -eq 0) {
        'PARTIAL - nothing escaped with the rule up first, but the after-spawn case leaked nothing either, so this run does not demonstrate that ordering matters. Widen PostSpawnDelaySeconds and re-run before relying on it'
    }
    elseif (-not $beforeSilent) {
        'ITEM 4 REFUTED - traffic escaped despite enforcement being in place before spawn'
    }
    else { 'UNEXPECTED - review the per-case counts' }

[pscustomobject]@{
    RunId               = $runId
    Target              = "${TargetIp}:${TargetPort}"
    ResearchBrowser     = $ResearchBrowserPath
    Version             = (Get-Item -LiteralPath $ResearchBrowserPath).VersionInfo.ProductVersion
    PostSpawnDelaySecs  = $PostSpawnDelaySeconds
    NoRule_Tx           = $none.Tx
    NoRule_Endpoints    = $none.Endpoints
    Before_Tx           = $before.Tx
    Before_Endpoints    = $before.Endpoints
    After_Tx            = $after.Tx
    After_Endpoints     = $after.Endpoints
    RuleRemoved         = $ruleGone
    FiltersCleared      = $filtersCleared
    Verdict             = $verdict
}
