<#
    Shared plumbing for the ADR-0001 verification-register prototypes.

    The measurement these scripts share: launch one browser installation, point it at an off-box
    address, and count what actually left the NIC. Observation is pktmon counters rather than
    anything the browser reports, because the questions being asked ("did a packet escape",
    "did the rule bite") are answered on the wire, and a browser that has been comprehensively
    blocked still renders an error page that looks the same as a DNS failure.

    Two properties of the target matter and are easy to get wrong:

    * It must be OFF this machine. Windows treats traffic to the host's own address as loopback
      and exempts it from outbound filtering, so a canary listening here is reached even by a
      process that is fully blocked -- every case passes and the test lies.
    * Nothing needs to listen on it. A blocked process emits zero SYNs; an unblocked one emits
      SYNs regardless of whether anything answers. Using a dead port means the only thing that
      can generate traffic toward it is the browser under test, so the counter cannot be
      polluted by unrelated activity.
#>

Set-StrictMode -Version Latest

function Invoke-Quietly {
    <#
    .SYNOPSIS
        Runs a block with native-command stderr demoted from a terminating error.
    .DESCRIPTION
        taskkill on an already-dead pid, and pktmon stop when nothing is capturing, both write a
        benign line to stderr. Under $ErrorActionPreference='Stop' PowerShell 5.1 promotes that
        to a terminating NativeCommandError, which tends to fire inside a finally block and take
        the cleanup -- and the run's results -- with it. Piping with 2>&1 makes it worse by
        feeding the error record back into the pipeline.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [scriptblock] $Block)

    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $Block 2>$null } catch { } finally { $ErrorActionPreference = $prev }
}

function Stop-ProcessTree {
    <#
    .SYNOPSIS
        Kills a process and its children. Silent if it has already exited.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [int] $ProcessId)

    Invoke-Quietly { & taskkill.exe /PID $ProcessId /T /F | Out-Null }
}

function Get-PktmonTxCounters {
    <#
    .SYNOPSIS
        Splits pktmon's Tx counters into packets that were transmitted and packets that were
        dropped before transmission.
    .DESCRIPTION
        pktmon reports one row per component, and the Counter column says which kind of row it
        is: Upper/Lower are packets moving through that component, Drops are packets discarded
        there. Both carry a Tx number, so reading Tx without reading the Counter column reports
        dropped packets as sent.

        That distinction is invisible for TCP -- a connect() refused by a filter never produces
        a packet at all, so a blocked case simply reports nothing. It is decisive for UDP, where
        a connectionless sendto() does produce a packet that the filter then drops: the naive
        reading turns successful enforcement into an apparent leak. Found 2026-09-04 while
        verifying register item 5, where it had produced a false "enforcement gap".

        Drops are worth surfacing rather than merely excluding. A drop count proves the
        application tried and enforcement caught it, which is stronger evidence than silence --
        silence cannot distinguish "blocked" from "never ran".
    .OUTPUTS
        [pscustomobject] with Transmitted and Dropped packet counts.
    #>
    [CmdletBinding()]
    param()

    $text        = (Invoke-Quietly { & pktmon.exe counters } | Out-String)
    $transmitted = 0
    $dropped     = 0

    # Anchor on the token immediately before "Rx", which is the Counter column. Two details in
    # pktmon's layout make the obvious patterns wrong, both found the hard way on 2026-09-04:
    # counts are printed with thousands separators (1,800), so \d+ silently fails to match and
    # every row reads as zero; and a component's second and later rows repeat neither its Id nor
    # its Name, so anchoring the line on a leading number drops the "Lower" row entirely.
    foreach ($line in ($text -split "`r?`n")) {
        if ($line -match '(\S+)\s+Rx\s+[\d,]+\s+[\d,]+\s*\|\s*Tx\s+([\d,]+)\s+[\d,]+') {
            $counter = $Matches[1]
            $tx      = [int]($Matches[2] -replace ',', '')
            if ($counter -eq 'Drops') {
                if ($tx -gt $dropped)     { $dropped = $tx }
            }
            elseif ($tx -gt $transmitted) { $transmitted = $tx }
        }
    }

    return [pscustomobject]@{ Transmitted = $transmitted; Dropped = $dropped }
}

function Get-TxPacketCount {
    <#
    .SYNOPSIS
        Packets that actually left the NIC; 0 when nothing was transmitted. Dropped packets do
        not count as egress -- see Get-PktmonTxCounters.
    #>
    [CmdletBinding()]
    param()

    return (Get-PktmonTxCounters).Transmitted
}

function Measure-BrowserEgress {
    <#
    .SYNOPSIS
        Launches one browser at an off-box target and returns how many packets reached the NIC.
    .PARAMETER ExtraArgs
        Additional Chromium switches for this case, e.g. a --proxy-server to test flag-based
        hardening. The browser always gets its own throwaway --user-data-dir.
    .OUTPUTS
        [int] Tx packet count toward TargetIp:TargetPort during the dwell window.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]   $Exe,
        [Parameter(Mandatory)] [string]   $Tag,
        [Parameter(Mandatory)] [string]   $TargetIp,
        [Parameter(Mandatory)] [int]      $TargetPort,
        [int]      $DwellSeconds = 12,
        [string[]] $ExtraArgs    = @()
    )

    Invoke-Quietly { & pktmon.exe stop | Out-Null }
    Invoke-Quietly { & pktmon.exe filter remove | Out-Null }
    Invoke-Quietly { & pktmon.exe filter add MinaProbe -i $TargetIp -p $TargetPort | Out-Null }
    Invoke-Quietly { & pktmon.exe start --capture --counters-only | Out-Null }

    $dir = Join-Path $env:TEMP ('mina-probe-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + "-$Tag")
    $argv = @(
        '--headless=new'
        "--user-data-dir=$dir"
        '--no-first-run'
        '--no-default-browser-check'
        '--disable-gpu'
    ) + $ExtraArgs + @("http://${TargetIp}:${TargetPort}/$Tag")

    $proc = Start-Process -FilePath $Exe -WindowStyle Hidden -PassThru -ArgumentList $argv
    try {
        Start-Sleep -Seconds $DwellSeconds
    }
    finally {
        Stop-ProcessTree $proc.Id
        Invoke-Quietly { & pktmon.exe stop | Out-Null }
        Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
    }

    return Get-TxPacketCount
}

function Clear-ProbeCapture {
    <#
    .SYNOPSIS
        Leaves pktmon as it was found: capture stopped, probe filters removed.
    #>
    [CmdletBinding()]
    param()

    Invoke-Quietly { & pktmon.exe stop | Out-Null }
    Invoke-Quietly { & pktmon.exe filter remove | Out-Null }
    return ((Invoke-Quietly { & pktmon.exe filter list } | Out-String) -notmatch 'MinaProbe')
}

Export-ModuleMember -Function Invoke-Quietly, Stop-ProcessTree, Get-TxPacketCount,
                              Get-PktmonTxCounters, Measure-BrowserEgress, Clear-ProbeCapture
