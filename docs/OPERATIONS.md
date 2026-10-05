# Operations Baseline

## Required runbooks before production

Written in `docs/RUNBOOKS.md` (M4-6, 2026-10-04) unless noted; the number is the section there.

| Runbook | Where |
|---|---|
| Egress region unavailable | RUNBOOKS 1 |
| Published DMZ control-plane endpoint unreachable (nodes cannot pull their session view or ship telemetry; new tunnels refused within `AdmissionMaxViewAge`, renewals stop within one lease) | RUNBOOKS 2 |
| Control plane unavailable | RUNBOOKS 3 |
| Entra authentication unavailable | RUNBOOKS 4 |
| Key Vault or audit-anchor storage unreachable | RUNBOOKS 5 |
| Arc agent failure on a control-plane host (breaks SQL *and* Key Vault access, no stored credential by design) | RUNBOOKS 6 |
| On-premises SQL Server failure, backup and restore (M4-3, M4-22) | RUNBOOKS 7, `scripts/sql-backup-onprem.ps1`, `scripts/sql-restore-drill-onprem.ps1` |
| Proxmox host or cluster failure; control-plane host rebuild from `dev-onprem` | RUNBOOKS 8 |
| Suspected egress-node compromise | RUNBOOKS 9 |
| Endpoint agent/profile malfunction | RUNBOOKS 10, and "New Windows endpoint onboarding" below |
| Wazuh integration failure | RUNBOOKS 11 |
| SigNoz integration failure | RUNBOOKS 12 |
| Published-endpoint TLS certificate renewal | RUNBOOKS 13 |
| Egress region activation (D-11, M4-1) | RUNBOOKS 14 |
| Emergency disable of an egress region | RUNBOOKS 15 |
| Certificate/key/secret rotation — internal CA rollover is below (M4-2) | RUNBOOKS 16, "Internal CA rollover" below |
| Database schema migration | RUNBOOKS 17 |
| Rollback to previous release | RUNBOOKS 18 |
| Break-glass activation and post-use review | below, D-10a — PROPOSED, not ratified |
| Backup/restore summary and drill schedule (M4-3) | RUNBOOKS, final two sections; `scripts/backup-keyvault-ca.sh`, `scripts/drill-stamp-rebuild.sh` |

## Service level objectives

Proposed 2026-10-04 for the owner to ratify; the numbers are starting points chosen from the
design's own bounds, not measurements. Each names the metric it is measured by.

| SLO | Target | Measured by | Why this number |
|---|---|---|---|
| Session establishment success | 99.5% of attempts per calendar month, excluding refusals that are the policy working (`DeviceNotBound`, `RegionNotSelectable`, `AuthenticationContextRequired`) | `mina_session_establish_failures_total` by `reason` against `mina_session_establish_duration_seconds` count | a refused analyst has no research path at all; 0.5% is ~1 failed start per analyst per month at 50 users |
| Session establishment latency | p95 under 3 s | `mina_session_establish_duration_seconds` | one Key Vault sign plus one SQL round trip; slower means one of them is degrading |
| Control-plane availability (node listener) | 99.9% monthly, measured from outside | external probe of `https://<public_hostname>/healthz` | nodes stop admitting tunnels after 5 minutes without it; 99.9% is ~43 min/month, i.e. at most a handful of such episodes |
| Control-plane availability (management listener) | 99.5% monthly | corporate probe of the UI `/healthz` | approvals wait; analysts are not stopped |
| Suppression correctness | zero `sensitive_suppression_mismatch` events the platform did not raise itself as a test | `mina_suppression_mismatches_total`, Wazuh 100510 | not a rate: one is a node collecting under an approved suppression |
| Audit pipeline | anchors never more than 15 minutes behind the chain tip while Azure Storage is reachable; `/api/audit/verify` intact with all anchors matched at every check | `AuditVerificationDto` (`anchorsChecked`, `anchorsMatched`, `anchorProblems`) | the export runs every minute under a lease; 15 minutes tolerates lease hand-over |
| Recovery point (database) | 15 minutes of governance events | `scripts/sql-backup-onprem.ps1 -Type Log` schedule | the log-backup cadence; tighter is a schedule change |
| Recovery time (control plane) | 4 hours to restored service after a single-host loss | RUNBOOKS 8 drill timings | Windows hosts need Arc, SQL and deploy steps; the proxy is minutes |
| Telemetry delivery lag | 95% of node telemetry recorded within 60 s of the connection | node `ShipInterval` (10 s) plus ingest | beyond this, suppression and review views lag reality |

## Alert catalogue

Every alert names its source so an operator knows where it is defined. Severity: **page** wakes
someone; **ticket** is next business day.

| Signal | Source | Threshold | Severity | Runbook |
|---|---|---|---|---|
| `sensitive_suppression_mismatch` | Wazuh 100510 (critical floor 100505) | any | page | RUNBOOKS 9 |
| break-glass use | Wazuh 100511 | any | page | OPERATIONS below |
| `ca_rotation_status` critical | Wazuh 100531 | any | page | "Internal CA rollover" |
| `authz_denied` repeated for one user | Wazuh 100521 | 5 in 10 min, excluding `AuthenticationContextRequired` | ticket | — (investigate the user) |
| `client_tamper_suspected` clustering | Wazuh 100530 | 3 per device in 15 min | page | RUNBOOKS 10 |
| node-API request from outside the stamps' NAT prefixes | Wazuh 100610 (proxy log `mina_source_known=0`) | any | page | RUNBOOKS 9, or fix `node_source_cidrs` |
| node listener rate-limited | Wazuh 100620/100621 (`limit_req=REJECTED`) | any / 20 in 5 min from one source | ticket / page | RUNBOOKS 1 |
| proxy answering 5xx | Wazuh 100630 | 10 in 2 min | page | RUNBOOKS 2 |
| node listener unreachable externally | external probe of `/healthz` | 3 consecutive failures | page | RUNBOOKS 2 |
| session establishment failures | SigNoz `mina_session_establish_failures_total` by `reason` | rate above 5/min for reasons other than the three policy ones | page | RUNBOOKS 3/4/5 |
| session establishment latency | SigNoz `mina_session_establish_duration_seconds` | p95 over 3 s for 10 min | ticket | RUNBOOKS 5/7 |
| telemetry scrub drops | SigNoz `mina_telemetry_scrub_drops_total` | any increase | ticket | integrations/signoz/README (something is putting destinations into operational telemetry) |
| telemetry ingest stopped | SigNoz `mina_telemetry_items_total` | zero for 10 min while sessions are active | page | RUNBOOKS 1/2 |
| anchors behind | API log (export failures, `AuditAnchorException`); `/api/audit/verify` `anchorsChecked` not advancing | 15 min | page | RUNBOOKS 5 |
| anchors do not match | `/api/audit/verify` `anchorsMatched < anchorsChecked` or `anchorProblems` non-empty | any | page, security | RUNBOOKS 7 "then stop and escalate" |
| CA key use volume | Log Analytics (M4-24) `KeySign` on `mina-internal-ca` | outside expected session rate | ticket; page if unexplained | RUNBOOKS 9 |
| anchor storage or vault ARM operations | Azure Monitor alerts (`alert_email_receivers`, M4-26) | any | page | RUNBOOKS 5 (and it fires on your own apply — intended) |
| Arc agent disconnected | Azure Arc machine status | disconnected over 5 min | page | RUNBOOKS 6 |
| SQL backup failed or verify failed | scheduled task result; manifest not appended | one missed log backup | ticket; page after 1 h | RUNBOOKS 7 |
| restore drill overdue | calendar | 35 days | ticket | RUNBOOKS drills |
| edge certificate expiry | external probe | under 14 days | ticket | RUNBOOKS 13 |

## On-call handover pack

What the person taking the pager needs, in the order they need it.

1. **What the platform is, in one paragraph.** USER_MANUAL §1. Research browsing exits through
   Azure egress nodes; the control plane on Proxmox issues the sessions and keeps the audit chain;
   everything fails closed. "No traffic" is the safe state and the expected one during any failure.
2. **Where things are.** The three Proxmox hosts (`terraform output` in `environments/dev-onprem`:
   proxy, app, SQL), the Azure stamps and vault (`environments/dev`), SigNoz, Wazuh, the Cloudflare
   dashboard for the published hostname. Credentials: your own Entra account for Azure and the
   console; the Proxmox API token from the operations vault; SSH to the proxy from a corporate
   range; Windows hosts via the QEMU guest agent only (no RDP/WinRM, by design).
3. **The first ten minutes of any page.** (a) Is it everyone or one region? `/healthz` on the
   public hostname from a corporate host, then the stamps' backend health. (b) Is it the control
   plane? Both listeners' `/healthz`. (c) Is it Azure? Service health for Key Vault, Storage and the
   stamp regions. (d) Run `/api/audit/verify` and paste the response into the ticket before doing
   anything else — it is the baseline you will compare against after.
4. **What you may not do.** Hand-edit governance tables; relax Conditional Access or compliance;
   disable the scrub processors; re-root the CA locally; create a permanent logging exemption;
   deploy to production without the approval record (CLAUDE.md "Decisions you must not make
   silently"). If an incident seems to need one of these, it is a decision for the owner, not for
   on-call.
5. **Standing decisions still pending** (what you may be asked about and must not improvise):
   retention periods (DPO, M4-9), on-premises break glass (owner, D-10a), undecided requests
   lapsing (owner), customer-managed keys on the anchor store (owner, M4-25), HA (M4-22).
6. **Drill status.** The last run date and result of each drill in RUNBOOKS' drill table, stated,
   including any that were skipped.
7. **Known gaps at handover.** From BACKLOG.md's open rows: no Wazuh agent on the proxy yet (M3-5),
   office hours unset so off-hours flagging is inert, one of each control-plane host (no HA),
   anchors not `Locked` in dev.

## Monitoring
The SLOs and the alert catalogue above are the definitions; this list is the coverage they are
meant to give, kept so a gap is visible when a signal is added or removed:
- session establishment success/failure;
- control-plane availability/latency;
- egress-region health/capacity;
- protected-path failures;
- approval workflow failures;
- audit pipeline health;
- Wazuh/SigNoz integration health (a local hop since ADR-0006; no tunnel involved);
- Arc agent health on every control-plane host; Key Vault and anchor-storage reachability;
- CA key use volume and anchor access (Log Analytics, M4-24) against expected session rates;
- published node-facing endpoint: certificate expiry, error rate, rate-limit hits, source addresses
  outside the stamps' NAT prefixes — the last three come from the proxy's own access log since
  M4-14 (`mina.proxy.v1`, fields `status`, `limit_req`, `mina_source_known`), shipped to SigNoz by
  the collector on the proxy host and to Wazuh by the agent (rules 100610/100620/100621/100630).
  Suggested thresholds, to be tuned against the first weeks of real traffic: any `mina_source_known
  = 0` line (page — a stamp prefix is missing or something is probing); any `limit_req = REJECTED`
  (ticket — the limits are sized so a healthy fleet never hits them); ten 502/503/504 in two
  minutes (page — the control plane is unreachable from the DMZ, nodes will stop admitting tunnels
  within `AdmissionMaxViewAge`); nginx `active connections` from stub_status flat at the
  `connections_per_source` ceiling (a node stuck opening connections);
- suspicious/open-proxy indicators;
- break-glass use.

## New Windows endpoint onboarding

Verified end to end against a genuinely fresh VM on 2026-09-10 — every step below was actually run,
not written from the architecture and assumed to work. One structural gap still runs through this
procedure: **A6** (a real organisation-issued code-signing certificate) doesn't exist yet, so step 4's
certificates are still self-signed lab stand-ins. Their *distribution*, though, is no longer
manual — `endpoint-agent/packaging/New-MinaTrustedCertificateProfiles.ps1` (built 2026-09-10, live
in the tenant) pushes both certificates to every device assigned `Mina Analysts` via three Intune
device configuration profiles, the same way the Win32 apps already reach devices. Step 4 below
describes what those profiles do and how to verify they landed; run the script itself only when the
certificates change (a new lab certificate, or eventually the real A6 one).

### 1. Start from a genuinely fresh device
Don't reuse a VM with prior enrollment history, even from a wipe. Repeated snapshot-revert +
re-enrollment cycles were found to accumulate stale entries under
`HKLM:\SOFTWARE\Microsoft\Enrollments` (35+ on one real test device) — Windows itself later showed
a "bad enrollment" being detected and purged from a genuinely fresh device too (see step 4), so this
class of drift isn't unique to heavily-reused VMs, but it compounds fast on them. A clean VM with no
enrollment history removes one whole category of thing to debug later.

### 2. Join at OOBE as the organization — not via Company Portal afterward
At the very first OOBE screen, choose **"Set up for an organization" / "My organization owns it"**
and sign in directly with the analyst's own Entra account **before any local account exists**.
Confirmed: every device joined the other way (local account first, "Connect" via Settings → Access
work or school afterward) enrolled `managedDeviceOwnerType=personal`. A counter-test on 2026-09-10
also showed `personal` ownership doesn't by itself block anything that matters (see step 6) — but
the OOBE-first path is still what's documented and what's actually been exercised, so it remains the
one to follow.

Verify the join before doing anything else:
```powershell
dsregcmd /status
```
Check `AzureAdJoined: YES` and note the `DeviceId`. `MdmUrl` showing blank here is not itself a
fault — it was blank on a device that went on to work correctly.

### 3. Confirm (or force) MDM auto-enrollment
Entra join and MDM auto-enrollment are two separate steps and can visibly lag each other. Check:
```powershell
Get-ScheduledTask -TaskPath "\Microsoft\Windows\EnterpriseMgmt\*" -ErrorAction SilentlyContinue |
    Select-Object TaskPath, TaskName, State
```
Tasks present (`PushLaunch`, `PushRenewal`, a certificate-reattestation schedule) means enrollment
completed. **Nothing there after a few minutes does not always resolve itself** — on the 2026-09-10
test device it never did, and had to be forced:
```powershell
Start-Process "C:\Windows\System32\deviceenroller.exe" -ArgumentList "/c /AutoEnrollMDM" -Verb RunAs
```
Re-check the scheduled-task query above after ~30 seconds. **Known side effect**: forcing it this
way produced a "dual enrollment" — `Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-
Provider/Admin` logged Windows detecting and purging a second, bad enrollment ID on its own within
the first few sync cycles. This looked alarming but was self-healing and did not block anything
downstream; if the same log shows an enrollment ID being purged shortly after a forced auto-enroll,
that's consistent with this and not, on its own, a reason to start over.

### 4. The two required certificates — now pushed automatically, verify rather than import
Both are self-signed lab stand-ins (see A6, above) and both must land in `LocalMachine\Root` before
the device can do anything useful; the code-signing certificate additionally needs
`LocalMachine\TrustedPublisher`. As of 2026-09-10 this is no longer a manual step: three Intune
device configuration profiles, assigned to `Mina Analysts`, push both automatically on the device's
next policy sync — no re-enrollment needed, and nothing to do here beyond waiting for that sync and
checking it actually landed.

**a. Endpoint agent code-signing certificate** (`CN=Mina Lab Code Signing (NOT FOR PRODUCTION)`,
thumbprint `<code-signing thumbprint>`) — needed for `Detect.ps1`/`Install.ps1` to
load at all under the Win32 app's `-ExecutionPolicy AllSigned`. Pushed to **both** `Root` and
`TrustedPublisher` (a self-signed chain needs both; `New-MinaLabSigningCertificate.ps1`'s own
output explains why) by two separate profiles — `windows81TrustedRootCertificate` has no
`TrustedPublisher` destination at all (confirmed against this tenant's own Graph beta `$metadata`),
so the `TrustedPublisher` half is a custom OMA-URI profile against the `RootCATrustedCertificates`
CSP instead (`New-MinaTrustedCertificateProfiles.ps1`'s own header explains the split in full).

**b. Control-plane management-listener TLS certificate** (`CN=mina.example.org`, thumbprint
`<listener-certificate thumbprint>`) — needed for the tray to trust `mina.example.org:
8444` at all. Without it the tray fails closed with no obvious error: the region dropdown just stays
empty, which looks identical to a WAM/broker sign-in problem or a network-reachability problem from
the outside (both were checked and ruled out on the 2026-09-10 device before this was found to be
the actual cause). Root store only.

**Verify it actually landed** rather than assuming the profile sync worked:
```powershell
certutil -store Root | Select-String "Mina Lab Code Signing|mina.example.org"
certutil -store TrustedPublisher | Select-String "Mina Lab Code Signing"
```
If either is missing after a normal sync window (step 5's own timing guidance applies here too),
force it the same way as any other stuck Intune policy: `Restart-Service
IntuneManagementExtension -Force`, or fall back to a manual import while investigating:
```powershell
certutil -f -addstore Root "<path-to-cert>.cer"
certutil -f -addstore TrustedPublisher "<path-to-cert>.cer"   # code-signing cert only
```
Use `certutil -f`, not `Import-Certificate`: on a genuinely fresh VM the target store (most often
`TrustedPublisher`) may not exist yet, and `Import-Certificate` fails there with a generic "Access
is denied" that has nothing to do with permissions.

**Rerunning the profile script.** Only needed when a certificate itself changes — a regenerated
lab certificate (new thumbprint) or, eventually, the real A6 certificate replacing the lab one:
```powershell
.\endpoint-agent\packaging\New-MinaTrustedCertificateProfiles.ps1 `
    -CodeSigningCertPath <path>.cer -TlsCertPath <path>.cer -AssignToGroupName 'Mina Analysts'
```
Re-runnable by design, but **update means delete-then-recreate, not PATCH** — found live 2026-09-10:
`PATCH /deviceManagement/deviceConfigurations/{id}` is broken for both profile types here, failing
identically (generic `ModelValidationFailure`) for every field tried, including a completely empty
body, on both `beta` and `v1.0`. Not a payload problem, the endpoint itself — the script deletes the
stale profile and creates a fresh one instead, which is Graph's own documented workaround for a
resource whose PATCH doesn't work.

### 5. Let Intune enroll and sync — expect it to be slow, not silent
Settings → Accounts → Access work or school → the account → **Info** → **Sync**. Detection/install
cycles for Win32 apps are throttled well below the per-minute check-in cadence — even a full
`Restart-Service IntuneManagementExtension -Force` was observed producing a check-in that completed
in under two seconds with no app work attempted at all. Give it 15–30 minutes and more than one
check-in cycle before concluding anything is actually stuck. To check what's actually happened:
```powershell
Select-String -Path "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\AgentExecutor.log" -Pattern "Adding argument" | Select-Object -Last 20
```
`powershellDetection` entries with no certificate-load error confirm step 4a worked. A missing
`error from script =` value (empty, not the certificate-chain message) on both the x64 and ARM64
detection scripts is the actual green light.

### 6. Verify the tray end to end
Once the agent installs (Win32 app, `Mina Endpoint Agent` x64 or ARM64 depending on hardware) and
Edge Beta installs (its own independent Required assignment — device ownership, `personal` or
`company`, does not gate this; confirmed by direct counter-example 2026-09-10), open the tray:
- **Region dropdown populated with the approved/active regions** (currently just `spaincentral`) —
  confirms step 4b (TLS trust to the management listener) and a working WAM token. An empty
  dropdown with no other symptom is almost always step 4b, not a token/broker problem — check that
  first.
- **Start session** actually completes — the one verification step nothing short of a live browser
  can stand in for.

### What's still a known gap, not a mystery to re-debug
- A6 itself: step 4's certificates are still self-signed lab stand-ins, even though their
  distribution is now automated. Swapping in the real production certificate is a rerun of
  `New-MinaTrustedCertificateProfiles.ps1` with new `.cer` files, not new infrastructure.
- MDM auto-enrollment not firing natively at OOBE (step 3) has been seen on a genuinely fresh
  device; the cause hasn't been root-caused, only worked around. If it recurs, that workaround is
  known to work, but it isn't yet understood *why* the native path sometimes doesn't fire.

## Internal CA rollover (M4-2)

Verified against the real `mina-ca` tool and the real config it points at (2026-09-10) — the
"redistribution of the trust root" this runbook used to describe as one undifferentiated step
turned out to be two different things once actually traced through the code, corrected below.

**Check whether a rollover is due, first.**
```powershell
mina-ca rotation-check --vault <key_vault_uri>
```
Read-only against the vault — needs only the rights `mina-ca show` needs. Prints `Healthy`,
`Warning` (inside 365 days of expiry by default) or `Critical` (inside 90 days, or already
expired); `--warn-days`/`--critical-days` override the defaults.

**Reporting to Wazuh (M4-2's monitoring-integration decision, made 2026-09-11: Wazuh, not
SigNoz).** Add `--report-sql <connection-string> --environment prod`:
```powershell
mina-ca rotation-check --vault <key_vault_uri> --report-sql $SqlConnectionString --environment prod
```
This writes a `ca_rotation_status` audit event (EVENT_SCHEMAS.md) through the same hash-chained
audit store every other governance event uses — deliberately not a raw line appended to the Wazuh
delivery file, so the write carries the chain's own tamper-evidence. The **already-running**
`WazuhDeliveryBackgroundService` inside the deployed control-plane API picks the event up on its
next delivery tick and ships it with no separate Wazuh-side wiring; `integrations/wazuh/rules/
mina_rules.xml` (rule 100531) pages on a `Critical` result specifically, the same urgency class as
break-glass use. `--report-sql` needs write rights to the `Mina` database (the same
`Authentication=Active Directory Default` connection string the API itself uses — reuse it rather
than inventing a second credential) on top of `rotation-check`'s existing read-only vault rights;
omit the flag to check without reporting, exactly as before.

**Scheduling it.** Nothing calls `rotation-check` on its own — a Windows Scheduled Task on the app
host is the straightforward way to get a periodic run without building a new hosted-service
timer for a once-a-day check. **Not yet created against the live host — this is the runbook for
doing so, not a claim it has been.**
```powershell
$action = New-ScheduledTaskAction -Execute 'mina-ca.exe' -Argument `
    '--vault <key_vault_uri> --report-sql "<connection-string>" --environment prod' `
    -WorkingDirectory 'C:\inetpub\mina-api'   # or wherever mina-ca is published alongside the API
$trigger = New-ScheduledTaskTrigger -Daily -At 6am
Register-ScheduledTask -TaskName 'Mina CA rotation-check' -Action $action -Trigger $trigger `
    -User 'SYSTEM' -RunLevel Highest
```
**The one thing to verify live before trusting this runs cleanly**: `Authentication=Active
Directory Default` resolves through the app host's local Arc/HIMDS endpoint (see "SQL Server 2025 +
Arc" below), and today only `IIS AppPool\MinaApiPool` — the API's own app-pool identity — has been
explicitly granted Read&Execute on `C:\ProgramData\AzureConnectedMachineAgent\` (+ `...\Tokens\`)
and membership in the local **"Hybrid agent extension applications"** group. Those are per-identity
grants, not something the whole machine inherits — `SYSTEM` almost certainly does not have them yet
just because the task above names it. Either grant `SYSTEM` the identical two things the app pool
identity already has, or point the task at an identity that does, **before** relying on a scheduled
run actually succeeding rather than silently failing to reach SQL every time. Confirm with a manual
run first (`schtasks /Run /TN "Mina CA rotation-check"`, then check the audit trail's `/audit`
screen or the Wazuh side for the event) rather than trusting the task's own "Last Run Result".

**The two halves of "redistribute the trust root" are not symmetric — this is the part worth
knowing before starting.**

- **Egress nodes update themselves, with no action needed here.** A node's server-certificate
  request (`POST /api/nodes/{region}/certificate`, M2-2d) returns `CaCertificatePem` fresh in the
  same response as its own leaf certificate (`NodeCertificateDto`, `NodeEndpoints.cs`) — deliberate,
  so a node never needs Key Vault read access just to learn a certificate that is public material
  anyway. Every node picks up the new CA on its next certificate request/renewal.
- **Endpoint agents do not, and this is deliberate too.** `MinaAgentOptions.EgressCaCertificatePem`
  is "delivered with the agent package (out of band) rather than fetched from the control plane, so
  the tunnel's trust anchor does not depend on the same channel it authenticates" (the option's own
  doc comment) — an agent validating the egress server's certificate by asking the control plane
  which CA to trust would be trusting the channel it is trying to authenticate. This is the half
  that actually needs a manual step below.

**Rollover.**
1. `mina-ca rotation-check --vault <key_vault_uri>` — confirm this is actually due, or that there is
   another reason to roll over now (key compromise, not just schedule).
2. `mina-ca bootstrap --vault <key_vault_uri> --replace` — signs a new CA certificate with the
   vault's signing key and overwrites the stored one. **Every certificate issued under the old root
   stops validating from this moment**, not from whenever agents/nodes happen to pick up the new
   one — read that as "everything below needs to happen promptly," not as a leisurely rollout.
   Prints the new CA's PEM; keep the output, the next steps need it.
3. Nodes: nothing to do. Confirm at least one node has actually re-requested its certificate since
   step 2 (its `NotBefore` in `IntuneManagementExtension`-style node logs, or simply wait one lease
   period) before considering the rollover complete for research sessions.
4. Endpoint agents: replace `endpoint-agent/packaging/egress-ca.pem` (the file
   `package.config.json`'s `egressCaCertificatePemPath` points at) with step 2's new PEM, then run
   the normal publish pipeline to ship it to every enrolled device:
   ```powershell
   .\endpoint-agent\packaging\Build-MinaEndpointPackage.ps1 -ConfigPath package.config.json -SigningCertificateThumbprint <thumbprint>
   .\endpoint-agent\packaging\Publish-MinaEndpointApp.ps1 -AssignToGroupName 'Mina Analysts'
   ```
   `Detect.ps1`'s version-string check (BACKLOG M2-5) means this reinstalls on every enrolled
   device, not just updates a config file in place — expected, not a symptom of anything wrong.
5. `mina-ca show --vault <key_vault_uri>` — confirm the vault now holds the new certificate and the
   control plane would start on it (the same load path the API itself uses).
6. Until every endpoint agent has actually received the republished package (Intune's own sync
   cadence, not instant — see "New Windows endpoint onboarding" above for what patience that
   requires), an agent still running the old package will fail every session with a certificate
   validation error against the egress server — fail-closed, not a leak, but worth knowing to
   expect rather than re-diagnosing as a new defect.

## Break-glass activation (on-premises plane, D-10a) — draft, PROPOSED and not yet ratified

D-10a itself is a proposal, not an owner-decided mechanism — nothing below should be treated as an
approved procedure until the owner has reviewed and ratified it. Not yet buildable end-to-end
either way: the dedicated Proxmox-level credential is only a design, the alerting half needs M3-5
(Wazuh delivery from the on-premises relay, not started), and a cloud-init-based scaffold that was
tried for the proxy host was found, by testing it for real, to force a destructive rebuild of the
live VM and was reverted rather than kept. Recorded now, in this state, so the procedure exists to
review before any of the mechanism does, not silently built and used first.

**When to use this.** Entra sign-in is unavailable *and* the normal `mina-admin` operational path
cannot recover the on-premises plane — not for routine administration, which uses `mina-admin`
through the QEMU guest agent the way every deploy script already does.

**What this is not for.** Directly hand-editing session or approval state in SQL to manufacture a
decision. Every such write must go through the application's own authenticated path — the
`Sessions` and `SensitiveSessionRequests` tables carry **no tamper-evidence of their own** (only
`AuditEvents` is hash-chained, D-18), so an out-of-path edit to either would not even be
*detectable*, let alone caught. Break-glass restores the *infrastructure* — Proxmox itself, a
stopped service, a host rebuild from `dev-onprem` — not a way around the application. Restoring SQL
from backup is a listed exception below and is itself an unresolved tension (D-10a): it is also a
bulk write outside the app's path, and can roll the audit chain back below an already-anchored
point with no reconciliation procedure written yet. Treat a restore as needing the same post-use
scrutiny as everything else here, not as pre-approved.

**Activation.**
1. Retrieve the vaulted break-glass credential from management custody (two-person retrieval,
   matching the Entra emergency-account procedure this extends — D-10).
2. Authenticate to Proxmox with it, not with the routine `mina-admin`/root key. This is what makes
   the use distinguishable at all — using the routine key for an emergency defeats the entire
   design and leaves no separate signal to alert on.
3. Do the minimum necessary to restore the normal path (restart a service, fix networking, restore
   from backup per the Proxmox/SQL-restore runbooks above) and stop.

**Post-use review, every time, no exceptions.**
1. Confirm the Wazuh alert fired (once M3-5 exists) and correlate it against the activation record.
   Until then: confirm manually from Proxmox's own access log and the host's auth log that the
   login is present, attributable, and time-bounded.
2. Record what was done, by whom, and why, in the same place Azure break-glass post-use reviews are
   recorded (D-10).
3. Run `GET /api/audit/verify` and confirm the chain is intact — this is the check the platform
   already has, and it is authoritative for the `AuditEvents` table specifically. It says nothing
   about `Sessions` or `SensitiveSessionRequests`, which have no equivalent today: for those,
   reviewing what the credential-holder actually did (step 2) is the only check that exists,
   because there is no automated one to run.
4. Rotate the credential if there is any doubt it stayed within the two people who retrieved it.
