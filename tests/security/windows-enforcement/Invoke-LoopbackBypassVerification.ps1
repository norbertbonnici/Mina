#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Measures whether the research browser can reach services on the analyst's own machine
    without going through the agent's proxy, and whether a bypass-list flag closes that.

.DESCRIPTION
    ADR-0001's fail-closed claim is that the research browser's only route out is the agent's
    loopback proxy. Two Windows/Chromium behaviours meet in a way that puts a hole in that for
    loopback destinations specifically:

      * Chromium exempts loopback from proxying by default, so a page can address 127.0.0.1
        directly even under a fixed proxy.
      * Windows does not filter loopback, so the C2 image-path rules -- which stop everything
        else -- do not stop this either.

    Neither is a defect on its own and both are documented elsewhere in this repo; the question
    is whether together they let a research page reach services on the endpoint (a local
    development server, an admin console on 127.0.0.1, an agent's own IPC surface).

    The discriminator is a proxy that is not listening. If the browser reaches a loopback service
    while its only configured route is a dead proxy, it did not use the proxy.

      1 no proxy configured                  expect HIT      the method detects a reach
      2 dead proxy, default bypass           expect HIT      loopback bypasses the proxy -- the gap
      3 dead proxy + --proxy-bypass-list     expect NO HIT   the flag closes it
      4 dead proxy + C2 image-path block     expect HIT      WFP does not cover loopback either

    Case 4 is what makes this worth fixing rather than noting: it establishes that the network
    layer is not a backstop here, so the browser-level flag is the only available control.

.NOTES
    Interpreting case 3. A no-hit is only meaningful if the flag actually reached the browser --
    `<` and `>` in --proxy-bypass-list=<-loopback> are characters a shell can eat. The script
    therefore reports the exact argument vector it launched with, so a "closed" result can be
    checked against what was really passed rather than what was intended.

    This does NOT establish that the flag is safe to ship. With the bypass removed, loopback
    destinations are sent to the proxy instead -- which is correct, and at the egress they meet
    the node's own refusal of loopback and private destinations (M4-10). But whether the browser
    can still reach the proxy itself, which also lives on loopback, needs a live proxy to answer
    and is checked separately against the demo harness.
#>
[CmdletBinding()]
param(
    [Parameter()] [int]    $ServicePort   = 18096,
    [Parameter()] [int]    $DeadProxyPort = 19999,
    [Parameter()] [string] $ResearchBrowserPath = 'C:\Program Files (x86)\Microsoft\Edge Beta\Application\msedge.exe',
    [Parameter()] [int]    $DwellSeconds  = 15
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'MinaEnforcementProbe.psm1') -Force

if (-not (Test-Path -LiteralPath $ResearchBrowserPath)) { throw "Browser not found at $ResearchBrowserPath" }
if (Get-NetTCPConnection -State Listen -LocalPort $DeadProxyPort -ErrorAction SilentlyContinue) {
    throw "Something is listening on $DeadProxyPort. The proxy must be dead for this test to discriminate."
}

$runId     = [guid]::NewGuid().ToString('N').Substring(0, 8)
$ruleName  = "MINA-LOOPBACK-$runId"
$deadProxy = "http://127.0.0.1:$DeadProxyPort"

$hits     = New-Object System.Collections.ArrayList
$launched = @{}
$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add("http://127.0.0.1:$ServicePort/")
$listener.Start()
$ctxTask = $listener.GetContextAsync()

function Invoke-Pump {
    param([int]$Ms = 300)
    $deadline = (Get-Date).AddMilliseconds($Ms)
    while ((Get-Date) -lt $deadline) {
        if ($script:ctxTask.IsCompleted) {
            try {
                $ctx = $script:ctxTask.Result
                [void]$script:hits.Add($ctx.Request.Url.AbsolutePath)
                $b = [Text.Encoding]::UTF8.GetBytes('ok')
                $ctx.Response.OutputStream.Write($b, 0, $b.Length)
                $ctx.Response.Close()
            } catch { }
            $script:ctxTask = $script:listener.GetContextAsync()
        }
        Start-Sleep -Milliseconds 100
    }
}

function Test-ReachesLocalService {
    param([string]$Tag, [string[]]$ExtraArgs = @())

    $dir  = Join-Path $env:TEMP "mina-lb-$runId-$Tag"
    $path = "/$Tag"
    $argv = @(
        '--headless=new'
        "--user-data-dir=$dir"
        '--no-first-run'
        '--no-default-browser-check'
        '--disable-gpu'
    ) + $ExtraArgs + @("http://127.0.0.1:$ServicePort$path")
    $launched[$Tag] = ($argv -join ' ')

    $proc = Start-Process -FilePath $ResearchBrowserPath -WindowStyle Hidden -PassThru -ArgumentList $argv
    try {
        $deadline = (Get-Date).AddSeconds($DwellSeconds)
        while ((Get-Date) -lt $deadline -and -not ($hits -contains $path)) { Invoke-Pump -Ms 300 }
    }
    finally {
        Stop-ProcessTree $proc.Id
        Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
    }
    return ($hits -contains $path)
}

$cases = [ordered]@{}
try {
    $cases['1 no proxy']                       = Test-ReachesLocalService 'noproxy'
    $cases['2 dead proxy, default bypass']     = Test-ReachesLocalService 'deadproxy' @("--proxy-server=$deadProxy")
    $cases['3 dead proxy + bypass-list']       = Test-ReachesLocalService 'bypasslist' @("--proxy-server=$deadProxy", '--proxy-bypass-list=<-loopback>')

    New-NetFirewallRule -DisplayName $ruleName -Name $ruleName -Direction Outbound `
        -Action Block -Program $ResearchBrowserPath -Profile Any -Enabled True | Out-Null
    $cases['4 dead proxy + C2 image-path block'] = Test-ReachesLocalService 'wfp' @("--proxy-server=$deadProxy")
}
finally {
    Invoke-Quietly { Remove-NetFirewallRule -Name $ruleName | Out-Null }
    try { $listener.Stop(); $listener.Close() } catch { }
}

$ruleGone = -not [bool](Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue)
$c1 = $cases['1 no proxy']
$c2 = $cases['2 dead proxy, default bypass']
$c3 = $cases['3 dead proxy + bypass-list']
$c4 = $cases['4 dead proxy + C2 image-path block']

$verdict =
    if (-not $c1)          { 'INCONCLUSIVE - the browser did not reach the local service even unrestricted; the measurement is broken' }
    elseif (-not $c2)      { 'NO GAP - loopback did not bypass the proxy on this build; the concern does not reproduce' }
    elseif ($c3 -and $c4)  { 'GAP CONFIRMED, FLAG INEFFECTIVE - loopback bypasses the proxy, WFP does not stop it, and --proxy-bypass-list did not close it either. Check the launched argument vector before concluding the flag is useless' }
    elseif ($c3)           { 'GAP CONFIRMED, FLAG INEFFECTIVE - --proxy-bypass-list did not close the bypass. Check the launched argument vector' }
    elseif ($c4)           { 'GAP CONFIRMED, FLAG WORKS - loopback bypasses the proxy and WFP does not stop it, but --proxy-bypass-list=<-loopback> does' }
    else                   { 'GAP CONFIRMED, FLAG WORKS - and the image-path block also stopped it, which is unexpected for loopback; re-check case 4' }

[pscustomobject]@{
    RunId           = $runId
    LocalService    = "127.0.0.1:$ServicePort"
    DeadProxy       = $deadProxy
    BrowserVersion  = (Get-Item -LiteralPath $ResearchBrowserPath).VersionInfo.ProductVersion
    Cases           = $cases
    LaunchedArgs    = $launched
    HitsRecorded    = @($hits)
    RuleRemoved     = $ruleGone
    Verdict         = $verdict
}
