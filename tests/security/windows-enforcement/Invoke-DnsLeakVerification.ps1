#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Measures whether the research browser resolves hostnames itself while proxied, or leaves
    resolution to the proxy the way an HTTP CONNECT tunnel is supposed to.

.DESCRIPTION
    M1-6 (AC-005) and THREAT_MODEL N12 ask whether the endpoint's own DNS resolver ever sees a
    research hostname before the request reaches the proxy. This platform's proxying is HTTP
    CONNECT: for an `https://` navigation through `--proxy-server`, the browser is meant to send
    the target hostname *in the CONNECT request* and let whatever is on the other end resolve it
    -- it should never call the OS resolver for the target itself. If it did, a research hostname
    would sit in the corporate resolver's logs and in Windows' own DNS client cache in plain
    sight, which is exactly the leak AC-005 exists to rule out.

    Measured categorically, not by counting: pktmon captures full packets (`--capture`, not
    `--counters-only`) to a temporary ETL file, filtered to this machine's own configured DNS
    server IPs on port 53 (`Get-DnsClientServerAddress`, not hardcoded), then `pktmon etl2txt`
    decodes it and this script greps the decoded text for the literal target hostname. A DNS query
    packet carries the queried name in cleartext on the wire (confirmed live: `pktmon etl2txt`
    decodes a real query into a tcpdump-style line ending `A? <name>.` before this script trusted
    it), so "was this specific hostname queried" is a yes/no fact to read off the capture, not a
    packet count to guess a threshold for.

    That replaces an earlier version of this script that counted Tx packets against a fixed
    threshold, found (by an adversarial review of this repo's own work, not by guessing) to be
    unsound: idle background chatter on this shared, busy admin workstation could plausibly produce
    single-digit packet counts indistinguishable from a real 1-2-hostname leak, so no threshold
    could safely separate "noise" from "a small real leak" -- exactly the failure mode a leak test
    exists to catch. The Windows DNS Client Operational ETW log was tried before either of those
    and abandoned for a different reason: Chromium's own built-in async DNS resolver sends raw UDP
    directly and bypasses the OS resolver API that log instruments, so it silently read "no
    resolution happened" even in the unproxied sanity case, where resolution provably did happen.

      1 no proxy, direct navigation          expect QUERIED       the target hostname is queried and the method
                                                                     can see it in the capture -- the method works
      2 proxied, live proxy                  expect NOT QUERIED   CONNECT carries the hostname; resolution is not
                                                                     this process's job once a proxy is configured
      3 proxied, dead proxy                  expect NOT QUERIED   even a failed CONNECT attempt should not have
                                                                     resolved the name first
      4 proxied, production flags            expect NOT QUERIED   the actual shipped flag set
                                                                     (edge-integration/research-browser-flags.json) --
                                                                     substantially the same claim as case 2, since
                                                                     none of the extra flags there bear on DNS, kept
                                                                     mainly as a drift check against that file

.NOTES
    Cases 2 and 4 also record whether the stand-in proxy actually received a CONNECT for the
    target hostname during the dwell window, not just whether DNS stayed silent -- silence alone
    cannot tell "the browser used the proxy correctly" apart from "the browser did nothing at all",
    and a case 1 that shows QUERIED already rules out the second reading only for the unproxied
    control, not for the proxied cases where DNS silence is the very thing being asserted as good.

    Does not cover N12's other half: page-triggered DNS prefetch/preconnect hints
    (`<link rel="dns-prefetch">`), which need a loaded page containing them to exercise, and are
    explicitly deferred with `NetworkPredictionOptions` to the ADR-0007 decision this platform has
    not made yet (see BACKLOG M2-5's own "held with the ADR-0007 decision" note) -- not
    re-litigated here. THREAT_MODEL N12 also names a WFP DNS block for the research-browser binary
    as a defence-in-depth mitigation; not evidenced by this script either, which measures whether a
    leak happens at all, not every layer that would stop one if it did.

    This measures Windows/Chromium mechanics against a synthetic hostname, the same honesty
    boundary the rest of this directory's scripts operate inside: it does not drive traffic
    through a real analyst session against the live egress stamp, because that whole chain is
    still blocked on M2-1 (no Entra tenant/app roles yet) and the remaining part of M2-4 (WAM
    sign-in, browser launch). What this *does* prove is real and durable regardless: whether the
    browser's own resolution behaviour, under this platform's actual proxy configuration, ever
    puts a research hostname on the wire toward a DNS server at all.
#>
[CmdletBinding()]
param(
    [Parameter()] [string] $ResearchBrowserPath = 'C:\Program Files (x86)\Microsoft\Edge Beta\Application\msedge.exe',
    [Parameter()] [string] $TargetHostname       = 'example.com',
    [Parameter()] [int]    $LiveProxyPort        = 18097,
    [Parameter()] [int]    $DeadProxyPort        = 19998,
    [Parameter()] [int]    $DwellSeconds         = 12
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'MinaEnforcementProbe.psm1') -Force

if (-not (Test-Path -LiteralPath $ResearchBrowserPath)) { throw "Browser not found at $ResearchBrowserPath" }
if (Get-NetTCPConnection -State Listen -LocalPort $DeadProxyPort -ErrorAction SilentlyContinue) {
    throw "Something is listening on $DeadProxyPort. The dead-proxy case must be dead to discriminate."
}

$resolverIps = @(Get-DnsClientServerAddress -AddressFamily IPv4 |
    Where-Object { $_.ServerAddresses.Count -gt 0 } |
    Select-Object -ExpandProperty ServerAddresses -Unique)
if ($resolverIps.Count -eq 0) { throw 'No configured IPv4 DNS servers found to scope the capture filter to.' }

$runId = [guid]::NewGuid().ToString('N').Substring(0, 8)

# A minimal CONNECT-capable stand-in: accepts the tunnel, records the request line, answers 200,
# then closes without forwarding anywhere. Pumped cooperatively from the main thread during each
# case's dwell window, the same shape Invoke-LoopbackBypassVerification.ps1 uses for its
# HttpListener -- no background job/module dependency needed.
$proxyListener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $LiveProxyPort)
$proxyListener.Start()
$proxyAcceptTask = $proxyListener.AcceptTcpClientAsync()
$script:proxyRequests = New-Object System.Collections.Generic.List[string]

function Invoke-ProxyPump {
    param([int] $Ms = 300)
    $deadline = (Get-Date).AddMilliseconds($Ms)
    while ((Get-Date) -lt $deadline) {
        if ($script:proxyAcceptTask.IsCompleted) {
            try {
                $client = $script:proxyAcceptTask.Result
                $stream = $client.GetStream()
                Start-Sleep -Milliseconds 50
                if ($stream.DataAvailable) {
                    $buf = New-Object byte[] 4096
                    $read = $stream.Read($buf, 0, $buf.Length)
                    if ($read -gt 0) {
                        $firstLine = ([Text.Encoding]::ASCII.GetString($buf, 0, $read) -split "`r`n")[0]
                        [void]$script:proxyRequests.Add($firstLine)
                    }
                }
                $resp = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 Connection Established`r`n`r`n")
                $stream.Write($resp, 0, $resp.Length)
                $stream.Close(); $client.Close()
            } catch { }
            $script:proxyAcceptTask = $script:proxyListener.AcceptTcpClientAsync()
        }
        Start-Sleep -Milliseconds 100
    }
}

# The real shipped flag set (minus --user-data-dir/--proxy-server, which this test supplies
# itself so it can point at the loopback listener rather than the ephemeral agent port a real
# agent would pick) -- read from the actual config file rather than retyped, so this cannot drift
# from what M2-5 actually ships.
function Get-ProductionFlags {
    param([int] $ProxyPort)
    $configPath = Join-Path $PSScriptRoot '..\..\..\edge-integration\research-browser-flags.json'
    $config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
    $flags = $config.launchFlags | Where-Object {
        $_ -notmatch '^--user-data-dir=' -and $_ -notmatch '^--proxy-server='
    }
    return @("--proxy-server=http://127.0.0.1:$ProxyPort") + $flags
}

function Remove-DirectoryWithRetry {
    param([string] $Path, [int] $Attempts = 5)
    for ($i = 0; $i -lt $Attempts; $i++) {
        try { Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop; return }
        catch { Start-Sleep -Milliseconds 300 } # Edge can hold profile-directory file locks briefly after taskkill
    }
    Invoke-Quietly { Remove-Item -LiteralPath $Path -Recurse -Force }
}

function Test-HostnameQueried {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Exe,
        [Parameter(Mandatory)] [string] $Tag,
        [string[]] $ExtraArgs = @(),
        [switch]   $PumpProxy
    )

    Invoke-Quietly { & pktmon.exe stop | Out-Null }
    Invoke-Quietly { & pktmon.exe filter remove | Out-Null }
    foreach ($ip in $resolverIps) {
        Invoke-Quietly { & pktmon.exe filter add "MinaDns-$ip" -i $ip -p 53 | Out-Null }
    }
    $etlPath = Join-Path $env:TEMP "mina-dns-$runId-$Tag.etl"
    Invoke-Quietly { & pktmon.exe start --capture -f $etlPath | Out-Null }

    $script:proxyRequests.Clear()
    $dir = Join-Path $env:TEMP "mina-dns-$runId-$Tag"
    $argv = @(
        '--headless=new'
        "--user-data-dir=$dir"
        '--no-first-run'
        '--no-default-browser-check'
        '--disable-gpu'
        # Found live 2026-09-05 on mina-w11-01: this host's configured DNS servers are Cloudflare
        # (1.1.1.1/1.0.0.1), one of Chromium's built-in auto-detected DoH providers, and Edge's own
        # Secure DNS ("Automatic") upgrades to it independently of the OS-level setting this test
        # already checks (netsh dns show encryption showed Auto-upgrade=no -- that governs the OS
        # stub resolver, not Chromium's separate DoH implementation). A DoH lookup carries the query
        # inside a TLS-encrypted HTTPS body, invisible to a port-53 capture, so case 1's own sanity
        # check went silent even for a real, confirmed-working resolution. What AC-005 actually asks
        # is narrower than "does DNS ever touch the wire in any form": it's whether the browser
        # resolves the target itself instead of leaving it to the CONNECT tunnel, over whatever
        # transport. Forcing plain DNS restores that as a directly observable, cleartext signal
        # without changing the property under test -- applied to every case identically, so the
        # comparison stays apples-to-apples.
        '--disable-features=DnsOverHttps'
    ) + $ExtraArgs + @("https://$TargetHostname/")

    $proc = Start-Process -FilePath $Exe -WindowStyle Hidden -PassThru -ArgumentList $argv
    try {
        if ($PumpProxy) {
            $deadline = (Get-Date).AddSeconds($DwellSeconds)
            while ((Get-Date) -lt $deadline) { Invoke-ProxyPump -Ms 300 }
        }
        else {
            Start-Sleep -Seconds $DwellSeconds
        }
    }
    finally {
        Stop-ProcessTree $proc.Id
        Invoke-Quietly { & pktmon.exe stop | Out-Null }
        Remove-DirectoryWithRetry -Path $dir
    }

    $queried = $false
    if (Test-Path -LiteralPath $etlPath) {
        $txtPath = Join-Path $env:TEMP "mina-dns-$runId-$Tag.txt"
        Invoke-Quietly { & pktmon.exe etl2txt $etlPath --out $txtPath | Out-Null }
        if (Test-Path -LiteralPath $txtPath) {
            # pktmon etl2txt always emits a "Packet Filter" metadata line echoing each filter's own
            # configuration -- harmless here since the filters are keyed by resolver IP, not the
            # hostname this searches for, but excluded explicitly rather than relied on by
            # coincidence (Invoke-Ipv6LeakVerification.ps1's IP-keyed filter was not so lucky:
            # found live, the metadata line matched its own search target every time).
            $queried = [bool](Select-String -LiteralPath $txtPath -Pattern ([regex]::Escape($TargetHostname)) |
                Where-Object { $_.Line -notmatch 'Packet Filter' })
            Remove-Item -LiteralPath $txtPath -ErrorAction SilentlyContinue
        }
        Remove-Item -LiteralPath $etlPath -ErrorAction SilentlyContinue
    }

    [pscustomobject]@{
        Queried        = $queried
        ProxyReachedIt = if ($PumpProxy) { [bool]($script:proxyRequests -match [regex]::Escape($TargetHostname)) } else { $null }
    }
}

$cases = [ordered]@{}
try {
    $cases['1 no proxy']                 = Test-HostnameQueried $ResearchBrowserPath 'noproxy'
    $cases['2 proxied, live proxy']       = Test-HostnameQueried $ResearchBrowserPath 'liveproxy' @("--proxy-server=http://127.0.0.1:$LiveProxyPort") -PumpProxy
    $cases['3 proxied, dead proxy']       = Test-HostnameQueried $ResearchBrowserPath 'deadproxy' @("--proxy-server=http://127.0.0.1:$DeadProxyPort")
    $cases['4 proxied, production flags'] = Test-HostnameQueried $ResearchBrowserPath 'prodflags' (Get-ProductionFlags -ProxyPort $LiveProxyPort) -PumpProxy
}
finally {
    Invoke-Quietly { $proxyListener.Stop() }
    Clear-ProbeCapture | Out-Null
}

$c1 = $cases['1 no proxy'].Queried
$c2 = $cases['2 proxied, live proxy'].Queried
$c3 = $cases['3 proxied, dead proxy'].Queried
$c4 = $cases['4 proxied, production flags'].Queried
$proxySawIt2 = $cases['2 proxied, live proxy'].ProxyReachedIt
$proxySawIt4 = $cases['4 proxied, production flags'].ProxyReachedIt

$verdict =
    if (-not $c1) {
        'INCONCLUSIVE - the target hostname was not queried even unproxied; the measurement did not detect a real resolution attempt'
    }
    elseif ($c2 -or $c3 -or $c4) {
        "GAP - the browser queried '$TargetHostname' itself while proxied (live=$c2, dead=$c3, prodflags=$c4); it would reach the corporate resolver"
    }
    elseif (-not ($proxySawIt2 -or $proxySawIt4)) {
        "INCONCLUSIVE - DNS stayed silent while proxied, but the stand-in proxy never saw a CONNECT for '$TargetHostname' either (live=$proxySawIt2, prodflags=$proxySawIt4) -- cannot tell 'used the proxy correctly' apart from 'did nothing'"
    }
    else {
        "NO LEAK - '$TargetHostname' is queried unproxied and not queried once proxied (live=$c2, dead=$c3, prodflags=$c4), and the proxy itself did receive the CONNECT for it (live=$proxySawIt2, prodflags=$proxySawIt4), confirming the browser used the proxy rather than doing nothing"
    }

[pscustomobject]@{
    RunId          = $runId
    TargetHostname = $TargetHostname
    ResolverIps    = $resolverIps
    BrowserVersion = (Get-Item -LiteralPath $ResearchBrowserPath).VersionInfo.ProductVersion
    Cases          = $cases
    Verdict        = $verdict
}
