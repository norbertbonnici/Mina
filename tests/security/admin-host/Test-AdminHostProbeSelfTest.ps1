<#
.SYNOPSIS
    Falsifiability harness for the D-21 administration-host probe.

.DESCRIPTION
    Proves the probe's predicates would catch a real violation, without weakening the host.

    Every leg drives the SAME exported functions the probe uses. Nothing here modifies an ACL,
    creates a principal, installs a service or touches a real credential store: the ACL legs are
    literal SDDL strings evaluated in memory, and the CI legs are synthetic inventory records.

    The load-bearing leg is INCIDENT-INDIRECT. The ACE that caused this whole finding named a
    local GROUP whose member was NETWORK SERVICE. A predicate comparing ACL identity strings sees
    an unfamiliar name, has no rule for it, and returns clean. That leg must report a violation
    AND name the leaf principal, not merely the group.

    ANTI-VACUITY legs matter as much as the negative ones: without them the predicate could be
    "everything is a violation" and every other leg would still pass.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'MinaAdminHostProbe.psm1') -Force

$machineSid = ((Get-LocalUser -Name 'Administrator').SID.Value -replace '-500$', '') -replace '^S-1-5-21-', ''

# A real local group whose member is NETWORK SERVICE, for the indirection leg. The probe never
# creates principals, so this uses one that already exists and records which.
$indirectGroupSid = $null
$indirectGroupName = $null
foreach ($g in (Get-LocalGroup -ErrorAction SilentlyContinue)) {
    $members = @(Invoke-Quietly { Get-LocalGroupMember -SID $g.SID.Value -ErrorAction Stop })
    if ($members -and ($members | Where-Object { $_.SID.Value -eq 'S-1-5-20' })) {
        $indirectGroupSid = $g.SID.Value; $indirectGroupName = $g.Name; break
    }
}

$legs = New-Object System.Collections.ArrayList
function Add-AclLeg {
    param([string]$Id, [string]$Sddl, [ValidateSet('CLEAN','VIOLATION')][string]$Expect,
          [string]$MustName = $null, [string]$Why)
    $r = Test-AclExposure -Sddl $Sddl -MachineSid $machineSid -Path "(self-test $Id)"
    $pass = ($r.Status -eq $Expect)
    if ($pass -and $MustName) {
        $pass = [bool]($r.Findings | Where-Object { $_.ReachingPrincipal -like "*$MustName*" })
    }
    [void]$legs.Add([pscustomobject]@{
        Id = $Id; Arm = 'ACL'; Expected = $Expect; Actual = $r.Status; Pass = $pass; Why = $Why
        Detail = if ($r.Findings) { ($r.Findings | ForEach-Object { "$($_.ReachingPrincipal) via $($_.Via)" }) -join '; ' } else { '' }
    })
}

# ---- ACL arm -------------------------------------------------------------------------------
Add-AclLeg 'ACCEPTED-ONLY' 'O:BAG:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BA)' 'CLEAN' -Why `
    'anti-vacuity: only SYSTEM and Administrators. If this fails, every other CLEAN leg is meaningless.'

Add-AclLeg 'INCIDENT-DIRECT' 'O:BAG:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;S-1-5-20)' 'VIOLATION' `
    -MustName 'S-1-5-20' -Why 'NETWORK SERVICE granted read directly.'

if ($indirectGroupSid) {
    Add-AclLeg 'INCIDENT-INDIRECT' "O:BAG:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;$indirectGroupSid)" 'VIOLATION' `
        -MustName 'S-1-5-20' -Why `
        "THE INCIDENT: read granted to local group $indirectGroupName, whose member is NETWORK SERVICE. Must name the LEAF, not the group. This is the leg that catches a string-comparison predicate."
} else {
    [void]$legs.Add([pscustomobject]@{
        Id = 'INCIDENT-INDIRECT'; Arm = 'ACL'; Expected = 'VIOLATION'; Actual = 'SKIPPED'; Pass = $false
        Why = 'No local group with NETWORK SERVICE as a member exists to exercise indirection.'; Detail = '' })
}

Add-AclLeg 'NULL-DACL' 'O:BAG:BA' 'VIOLATION' -Why `
    'No D: at all means unrestricted. Get-Acl .Access is EMPTY here, so an ACE loop reports clean on the most open object possible.'

Add-AclLeg 'EMPTY-DACL' 'O:BAG:BAD:PAI' 'CLEAN' -Why `
    'An empty DACL grants nobody anything. Must not be confused with a null DACL.'

Add-AclLeg 'DENY-CANONICAL' 'O:BAG:BAD:PAI(D;;FA;;;S-1-5-20)(A;;FA;;;S-1-5-20)(A;;FA;;;BA)' 'CLEAN' -Why `
    'Deny precedes allow: correctly denied. A naive "is there an Allow ACE" predicate fails this safe descriptor.'

Add-AclLeg 'DENY-NONCANONICAL' 'O:BAG:BAD:PAI(A;;FA;;;S-1-5-20)(D;;FA;;;S-1-5-20)(A;;FA;;;BA)' 'VIOLATION' `
    -MustName 'S-1-5-20' -Why `
    'Allow precedes deny, so access IS granted. The dangerous direction: a naive predicate calls this safe.'

Add-AclLeg 'GENERIC-ALL' 'O:BAG:BAD:PAI(A;;GA;;;S-1-5-32-545)(A;;FA;;;BA)' 'VIOLATION' -Why `
    'GENERIC_ALL renders as a bare integer, not a FileSystemRights name. Matching on enum names misses it.'

Add-AclLeg 'ORPHANED-SID' "O:BAG:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;OICI;FA;;;S-1-5-21-$machineSid-4999)" 'VIOLATION' -Why `
    'Unresolvable SID holding FullControl. A future principal issued that RID inherits the access. This is the live shape on C:\actions-runner.'

Add-AclLeg 'TRAVERSE-ONLY' 'O:BAG:BAD:PAI(A;;0x100020;;;S-1-15-3-1024-1)(A;;FA;;;BA)' 'CLEAN' -Why `
    'Execute/traverse plus synchronize only, the shape of the AppX capability ACE on this profile root. Firing here trains the operator to ignore the check.'

Add-AclLeg 'READ-CONTROL-ONLY' 'O:BAG:BAD:PAI(A;;0x60000;;;S-1-5-32-545)(A;;FA;;;BA)' 'VIOLATION' -Why `
    'READ_CONTROL|WRITE_DAC with no read-data bit is still read-equivalent: rewrite the DACL, then read.'

Add-AclLeg 'INHERIT-ONLY' 'O:BAG:BAD:PAI(A;OIIO;FA;;;S-1-5-32-545)(A;;FA;;;BA)' 'CLEAN' -Why `
    'An inherit-only ACE grants nothing on the object itself.'

# ---- CI state arm --------------------------------------------------------------------------
function Add-StateLeg {
    param([string]$Id, [bool]$Svc, [bool]$Proc, [bool]$Markers, [bool]$Bins, [string]$Expect, [string]$Why)
    $actual = Get-CiAgentState -ServiceRunning $Svc -ProcessRunning $Proc -MarkersPresent $Markers -BinariesPresent $Bins
    [void]$legs.Add([pscustomobject]@{
        Id = $Id; Arm = 'CI-STATE'; Expected = $Expect; Actual = $actual; Pass = ($actual -eq $Expect); Why = $Why; Detail = '' })
}

Add-StateLeg 'STATE-OPERATIONAL'  $true  $false $true  $true  'OPERATIONAL'       'Running service with registration markers.'
Add-StateLeg 'STATE-STOPPED'      $false $false $true  $true  'REGISTERED-STOPPED' 'Markers on disk, service stopped. Credentials still authorise this host; one sc start restores it.'
Add-StateLeg 'STATE-RESIDUE'      $false $false $false $true  'RESIDUE'            'Binaries, no markers. Not a pass: re-arm assets and stale ACEs remain.'
Add-StateLeg 'STATE-CLEAN'        $false $false $false $false 'CLEAN'              'Anti-vacuity for the state model.'

# ---- verdict -------------------------------------------------------------------------------
$failed = @($legs | Where-Object { -not $_.Pass })
[pscustomobject]@{
    Result           = if ($failed.Count) { 'Failed' } else { 'Passed' }
    Legs             = @($legs)
    FailedCount      = $failed.Count
    IndirectionGroup = $indirectGroupName
}
