<#
.SYNOPSIS
    AC-017: an egress node cannot reach internal, private or link-local destinations (M1-7).

.DESCRIPTION
    Runs connection attempts from a live egress node and asserts which of them fail. Since ADR-0006
    the approved set of private destinations is empty -- the control plane is reached at a public
    endpoint -- so no internal destination is carved out of the deny.

    There is exactly one exception in the ruleset, and it is a port rather than a destination:
    Envoy's DNS resolver is pinned to Azure's platform address (168.63.129.16:53), because the
    node's own resolv.conf points at a 127.0.0.53 stub the same rule rejects. So that address is
    probed three ways below -- denied on :80 and :32526, allowed on :53 -- and the :53 row is a
    control, not a hole being blessed: if it ever fails, node DNS is broken and every CONNECT 503s.
    A CONNECT *tunnelled* to any resolver port is refused a layer earlier, by the Envoy RBAC
    destination policy, because at the socket a tunnel and the resolver's own query are the same
    uid to the same address and port and cannot be told apart.

    The probes run as the mina-envoy service account, deliberately. That is the process that carries
    analyst traffic, and M4-10's nftables rule is scoped to its uid rather than applied host-wide:
    the node itself still needs link-local for IMDS (mina-install-sidecar.sh and mina-fetch-certs.sh
    both take managed-identity tokens from 169.254.169.254). A probe run as root would therefore
    report the opposite answer for link-local and prove nothing about research traffic.

    Two controls run alongside, because every real assertion here is a negative and a node with no
    network at all would pass all of them:

      * mina-envoy CAN reach a public address -- the deny is specific, not "nothing works".
      * root CAN reach IMDS -- the rule is uid-scoped, not a host-wide block that would break
        certificate and sidecar provisioning at the next boot.

.PARAMETER ResourceGroup
    Resource group of the egress stamp's scale set, e.g. rg-mina-dev-egress-spc.

.PARAMETER ScaleSet
    Scale set name, e.g. vmss-mina-dev-egress-spc.

.PARAMETER InstanceId
    Instance to probe. Defaults to 0.

.PARAMETER CorpPublicCidr
    Optional corporate public address to add to the denied set (AC-017 names corp public ranges
    alongside RFC1918). Skipped when not supplied -- this lab has none, and inventing one would
    assert against an address belonging to somebody else.

.PARAMETER ArtifactEndpointIp
    Private-endpoint address of the artifacts storage account (M4-29, D-22), if the environment has
    one. Adds two rows: root must reach it, because that is how a booting node fetches its sidecar,
    and mina-envoy must not, because analyst traffic has no business there. Skipped when not
    supplied -- the address is allocated by Azure, so a default would either rot or assert against
    an endpoint belonging to somebody else.

.EXAMPLE
    .\Invoke-NodeReachabilityProbe.ps1 -ResourceGroup rg-mina-dev-egress-spc `
        -ScaleSet vmss-mina-dev-egress-spc

.EXAMPLE
    # With the artifact endpoint's address read back from Azure rather than typed:
    $pe = az network private-dns record-set a show -g rg-mina-dev-artifacts `
            -z privatelink.blob.core.windows.net -n stminadevartifacts `
            --query "aRecords[0].ipv4Address" -o tsv
    .\Invoke-NodeReachabilityProbe.ps1 -ResourceGroup rg-mina-dev-egress-spc `
        -ScaleSet vmss-mina-dev-egress-spc -ArtifactEndpointIp $pe

.NOTES
    Read-only: it opens TCP connections and reports, changing nothing on the node. Requires an
    `az login` with rights to run commands on the scale set.

    Uses bash's /dev/tcp rather than curl or nc, so the probe measures the socket layer -- where
    both the NSG and the nftables rule act -- and not an HTTP client's own timeout behaviour.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[a-zA-Z0-9._\-()]{1,90}$')]
    [string]$ResourceGroup,

    [Parameter(Mandatory)]
    [ValidatePattern('^[a-zA-Z0-9._\-]{1,64}$')]
    [string]$ScaleSet,

    [ValidatePattern('^\d{1,5}$')]
    [string]$InstanceId = "0",

    [ValidatePattern('^(\d{1,3}\.){3}\d{1,3}$')]
    [string]$CorpPublicCidr,

    [ValidatePattern('^(\d{1,3}\.){3}\d{1,3}$')]
    [string]$ArtifactEndpointIp
)

$ErrorActionPreference = "Stop"

# host:port:expectation. "deny" means the connection must fail; "allow" is a control that must
# succeed, without which a dead node would pass every assertion.
$probes = @(
    @{ Target = "10.0.0.1";        Port = 443; Expect = "deny";  As = "mina-envoy"; What = "RFC1918 10/8" }
    @{ Target = "172.16.0.1";      Port = 443; Expect = "deny";  As = "mina-envoy"; What = "RFC1918 172.16/12" }
    @{ Target = "192.168.0.1";     Port = 443; Expect = "deny";  As = "mina-envoy"; What = "RFC1918 192.168/16" }
    @{ Target = "100.64.0.1";      Port = 443; Expect = "deny";  As = "mina-envoy"; What = "CGNAT 100.64/10" }
    @{ Target = "169.254.169.254"; Port = 80;  Expect = "deny";  As = "mina-envoy"; What = "link-local IMDS (M4-10's only control)" }
    @{ Target = "127.0.0.1";       Port = 8081; Expect = "deny"; As = "mina-envoy"; What = "loopback, where Envoy's own health listener sits" }
    @{ Target = "168.63.129.16";   Port = 80;  Expect = "deny";  As = "mina-envoy"; What = "Azure platform address: WireServer goal state and extension config" }
    @{ Target = "168.63.129.16";   Port = 32526; Expect = "deny"; As = "mina-envoy"; What = "Azure platform address: host GA plugin" }
    # The one carve-out in the whole chain, and it must be proven to still work: Envoy's resolver is
    # pinned to this address:port, and if it stops being reachable every CONNECT 503s on DNS. This
    # row is why the deny rows above cannot simply be widened to the whole address.
    @{ Target = "168.63.129.16";   Port = 53;  Expect = "allow"; As = "mina-envoy"; What = "CONTROL: the DNS port Envoy's pinned resolver depends on" }
    @{ Target = "1.1.1.1";         Port = 443; Expect = "allow"; As = "mina-envoy"; What = "CONTROL: the public internet, which research traffic must reach" }
    @{ Target = "169.254.169.254"; Port = 80;  Expect = "allow"; As = "root";       What = "CONTROL: IMDS as root, which node provisioning depends on" }
)

if ($CorpPublicCidr) {
    $probes += @{ Target = $CorpPublicCidr; Port = 443; Expect = "deny"; As = "mina-envoy"; What = "corporate public address" }
}

# The artifacts storage account's private endpoint (M4-29, D-22), when the environment has one. Two
# rows because the two answers must differ, and each is load-bearing on its own:
#
#   * as root, REACHED -- this is the path mina-install-sidecar.sh fetches the node's own binary
#     over at boot. It is here because it failed on 2026-09-07: the endpoint's address is RFC1918,
#     the stamp NSG denies that space, and the node resolved the account and then could not connect.
#     Nothing noticed until a reimage produced a node with no sidecar. This row is the check that
#     would have.
#   * as mina-envoy, BLOCKED -- analyst traffic must not reach the artifact store through the
#     tunnel, and D-22 claims it cannot: the hostname now resolves into private space, which M4-10's
#     uid-scoped nftables rule rejects. That was an argument from the ruleset until this row
#     measured it. The NSG allow above is deliberately not uid-aware, so this deny rests entirely on
#     nftables -- which is exactly why asserting it matters.
#
# Not defaulted: the address is allocated by Azure, so pinning one here would either rot or quietly
# assert against somebody else's endpoint. Read it from the private DNS zone -- which is also the
# address the node itself resolves, so the probe and the node agree by construction:
#   az network private-dns record-set a show -g <artifacts-rg> `
#     -z privatelink.blob.core.windows.net -n <storage-account> `
#     --query "aRecords[0].ipv4Address" -o tsv
# (`az network private-endpoint show --query customDnsConfigs` returns [] once a private DNS zone
# group is attached, which is the arrangement here -- it is not the way to find this address.)
if ($ArtifactEndpointIp) {
    $probes += @{ Target = $ArtifactEndpointIp; Port = 443; Expect = "deny"; As = "mina-envoy"
                  What   = "artifact store's private endpoint, which research traffic must not reach" }
    $probes += @{ Target = $ArtifactEndpointIp; Port = 443; Expect = "allow"; As = "root"
                  What   = "CONTROL: the artifact store the node fetches its sidecar from at boot" }
}

# Built as one script so the whole set costs a single run-command round trip (each is ~20 s).
$lines = foreach ($p in $probes) {
    $runAs = if ($p.As -eq "root") { "" } else { "runuser -u $($p.As) -- " }
    "if $runAs timeout 4 bash -c '</dev/tcp/$($p.Target)/$($p.Port)' 2>/dev/null; then echo 'REACHED $($p.Target):$($p.Port)'; else echo 'BLOCKED $($p.Target):$($p.Port)'; fi"
}
# Joined with "; " rather than newlines. A multi-line string handed to `az ... --scripts` through
# PowerShell arrives split, and only the first line runs -- which looks exactly like a set of
# passing probes, because a probe that never ran produces no REACHED line either. Found the honest
# way: the first run reported one result and seven "did not run", which is why every probe is
# matched by name rather than counted.
$remoteScript = ($lines -join "; ")

Write-Host "==> Probing $ScaleSet instance $InstanceId ($($probes.Count) connections)" -ForegroundColor Cyan

$raw = az vmss run-command invoke `
    --resource-group $ResourceGroup `
    --name $ScaleSet `
    --instance-id $InstanceId `
    --command-id RunShellScript `
    --scripts $remoteScript `
    --query "value[0].message" -o tsv

if (-not $?) { throw "az vmss run-command invoke failed." }

$failures = @()
foreach ($p in $probes) {
    $key = "$($p.Target):$($p.Port)"
    # Each probe emits exactly one line; matched positionally by target:port rather than by order,
    # so a change to the probe list cannot silently misattribute a result.
    $reached = $raw -match [regex]::Escape("REACHED $key")
    $blocked = $raw -match [regex]::Escape("BLOCKED $key")

    if (-not ($reached -or $blocked)) {
        $failures += "no result for $key ($($p.What)) -- the probe did not run"
        Write-Host ("  ?  {0,-24} {1}" -f $key, $p.What) -ForegroundColor Yellow
        continue
    }

    $ok = if ($p.Expect -eq "deny") { $blocked } else { $reached }
    if ($ok) {
        Write-Host ("  OK {0,-24} {1} [{2}, as {3}]" -f $key, $p.What, $p.Expect, $p.As) -ForegroundColor Green
    }
    else {
        # Computed before interpolation: Windows PowerShell 5.1 mis-parses an if/else block inside
        # a $() subexpression in a double-quoted string.
        $actual = "blocked"
        if ($reached) { $actual = "reached" }
        $failures += "$key ($($p.What)) as $($p.As): expected $($p.Expect), got $actual"
        Write-Host ("  !! {0,-24} {1} [expected {2}, as {3}]" -f $key, $p.What, $p.Expect, $p.As) -ForegroundColor Red
    }
}

Write-Host ""
if ($failures.Count -gt 0) {
    Write-Host "FAIL — AC-017 not evidenced:" -ForegroundColor Red
    $failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    exit 1
}

Write-Host "PASS — the node reaches the public internet and nothing private, link-local or internal." -ForegroundColor Green
Write-Host "Raw output retained below for the evidence bundle (AC-019)." -ForegroundColor DarkGray
Write-Host $raw
exit 0
