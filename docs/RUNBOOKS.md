# Runbooks

Operational procedures for the Mina platform (M4-3, M4-6, M4-22). `docs/OPERATIONS.md` holds the
baseline: SLOs, the alert catalogue, the on-call handover pack, and the two long procedures that
were written there first (endpoint onboarding, internal CA rollover). This file holds everything
else the "Required runbooks before production" list in OPERATIONS.md names.

Conventions used throughout:

- **Fail closed is the design.** Every failure here lands on "no research traffic", never on
  "traffic took another path" (CLAUDE.md property 2). A runbook restores service; it never works
  around the fail-closed behaviour.
- **Nothing here edits governance state by hand.** Sessions, approvals and the audit chain are
  changed only by the application. If a step seems to need a direct write to `AuditEvents`,
  `Sessions` or `SensitiveSessionRequests`, stop: that is break glass (OPERATIONS.md, D-10a,
  PROPOSED), not operations.
- **Every incident ends with an audit-gap check.** `GET /api/audit/verify` on the management
  listener (Admin role) returns `intact`, `verified`, `anchorsChecked`, `anchorsMatched` and
  `anchorProblems`. "Intact" alone is not enough: the anchors are the tamper evidence (SECURITY_REVIEW
  #12). Record the response in the incident ticket.
- **Where to look.** SigNoz for the platform's own metrics and the proxy host's logs; Wazuh for
  the audit and security events (rule ids in OPERATIONS.md's alert catalogue); the Azure portal
  for the stamps, Key Vault and the anchor storage account; Proxmox for the three control-plane
  hosts. Nodes have no interactive management path by design; their only operator surface is
  Azure (reimage, scale, NSG) and the control plane's own view of them.

Environment facts referenced below come from Terraform outputs: `environments/dev` gives
`ingress_public_ip`, `egress_ip_prefix`, `key_vault_uri`, `audit_export_container_uri`,
`vmss_principal_id`; `environments/dev-onprem` gives `node_endpoint`, `proxy_ip`, `app_ip`,
`app_vm_id`, `sql_ip`, `sql_vm_id`, `listener_ports`.

---

## 1. Egress region unavailable

**Symptoms.** Analysts in that region see "Browsing stopped" (USER_MANUAL 4.7) and nothing else
changes. `mina_session_establish_failures_total{reason="RegionNotSelectable"}` is not the signal
(that is a configuration refusal); the signal is the stamp's load-balancer probe failing, or
`EnvoySessionAdmission` 503s in the nodes' access log reaching SigNoz as `ext_authz_error`.

**Impact.** Research browsing in the region pauses. Sessions, approvals and audit are unaffected;
they live on the control plane.

**Diagnose, in this order.**
1. Azure: the stamp's load balancer backend health. The probe is the node's `:8081/healthz`, which
   is 200 only while the node's sidecar holds a fresh session view. All nodes unhealthy at once
   almost always means the nodes cannot reach the control plane, not that Envoy is down — go to
   runbook 2.
2. One node unhealthy: reimage that instance from the scale set (the image is rebuilt from
   cloud-init; nothing on a node is state). Do not try to repair it in place; there is no path in.
3. Every tunnel 503 with `dns_resolution_failure` in the access log: the resolver pin
   (envoy-bootstrap.yaml, 168.63.129.16) — see the comment block in that file for the one time this
   happened and why `use_resolvers_as_fallback` must stay false on a real node.
4. Capacity: `active connections` from the stamp's nodes flat at a ceiling, or the NAT gateway's
   SNAT port exhaustion metric. Scale the set out (`instance_count`) rather than tuning.

**Act.** Reimage or scale as above. If the region cannot be restored within the time the business
accepts, remove it from `Mina:Regions:Active` on the API host (runbook 15) so analysts are not
offered a region that fails at the egress rather than at selection.

**Verify.** Backend health green; a test session from a lab endpoint tunnels; the node's
`mina.hostname.v1` lines resume in the control plane (`mina_telemetry_items_total{outcome="recorded"}`
for the region rising).

**Audit gap.** None on the control plane. Nodes buffer no telemetry across a reimage (they ship
from a tail, deliberately), so there is a telemetry gap for the affected node's tunnels during the
outage. Note the window in the ticket; it is operational data, not audit.

---

## 2. Published DMZ control-plane endpoint unreachable (control plane unreachable from the nodes)

**Symptoms.** Every region at once: nodes' session views age out, `/healthz` on every node goes
503 after `AdmissionMaxViewAge` (5 min default), new tunnels are refused with `ext_authz_denied`
(`ViewStale`), and within one lease (~60 min) analysts' sessions stop renewing. Wazuh rule 100630
(proxy answering 5xx) fires if the proxy is up but the app is not; nothing from the proxy at all
means the proxy host or the tunnel connector is down.

**Impact.** Research browsing stops platform-wide, in two steps: new tunnels within 5 minutes,
existing sessions within an hour. Failing closed at both horizons is correct. Approvals and the
management console are unaffected (corporate listener, different path).

**Diagnose, in this order.**
1. From a corporate host: `curl -sS https://<public_hostname>/healthz`. 200 means the chain is
   fine and the problem is at the nodes (runbook 1). A Cloudflare error page means the tunnel
   connector or its far end. A timeout means DNS or the connector.
2. On the proxy host (SSH from a corporate range): `systemctl status nginx`, then
   `tail /var/log/nginx/mina-node.access.json`. Lines with `"upstream_status":"502"` or `"504"`
   mean the app host's node listener is not answering: go to step 4. No lines at all: the
   connector is not delivering — `systemctl status cloudflared` on whatever host runs the
   connector, and its tunnel status in the Cloudflare dashboard.
3. `nft list ruleset` on the proxy: the only permitted source for `:80` is `tunnel_connector_cidr`.
   If the connector's address changed, this is the cause; fix the tfvars and re-apply, do not edit
   the ruleset by hand (cloud-init owns it and the next boot would undo you).
4. On the app host (QEMU guest agent exec, as the deploy scripts do; there is no RDP/WinRM):
   `Get-Website MinaApi`, `Get-WebAppPoolState MinaApiPool`, then
   `Invoke-WebRequest http://localhost:<NodePort>/healthz`. A stopped pool: start it, then look at
   the Windows event log for why it stopped (a startup validation failure — see OptionsValidation —
   logs the exact setting). A 500 on `/healthz`: SQL (runbook 7) or Arc (runbook 6).

**Act.** Restore whichever layer failed. For a dead proxy VM, rebuild it from `dev-onprem`
(runbook 8, proxy variant); it holds no state.

**Verify.** `/healthz` 200 end to end from a corporate host; node `/healthz` green in the stamps'
backend health within one refresh interval; sessions renewing again
(`mina_session_establish_duration_seconds` getting samples).

**Audit gap.** None: the audit chain is written by the control plane, which was up. Telemetry gap
for the outage window (nodes drop batches they cannot ship, by design — EVENT_SCHEMAS §6). Run
`/api/audit/verify` anyway and record it.

---

## 3. Control plane down entirely (application host)

**Symptoms.** Runbook 2's symptoms plus the management console failing: approvals cannot be made,
the UI's own `/healthz` (corporate listener, `ManagementPort`) is not 200.

**Impact.** No new sessions, no renewals, no approvals, no audit writes. Governance actions fail
closed (they do not proceed unlogged), so there is nothing to reconcile afterwards — there is
simply nothing recorded for the window, because nothing happened.

**Diagnose.** Proxmox first: is the VM running, does the guest agent answer. Then IIS as in
runbook 2 step 4. Both IIS sites (`MinaApi`, `MinaUi`) share the host; if only one is down the
other's event log entries usually name the cause.

**Act.** Restart the app pool; if the host is gone, runbook 8. Redeploy the last known-good build
with the deploy scripts if the pool refuses to start on a bad configuration you cannot correct
quickly (runbook 18).

**Verify.** Both listeners 200 on `/healthz`; a management-only route 404s on the node port (the
deploy script's own check — listener separation intact); `/api/audit/verify` intact with anchors
matched.

**Audit gap.** None by construction. Record the verify response.

---

## 4. Entra authentication unavailable

**Symptoms.** Analysts cannot start sessions (`mina_session_establish_failures_total` with token
reasons, or no requests at all because the agent cannot obtain a token); approvers cannot sign in
to the console. Existing sessions keep tunnelling until their lease lapses (~60 min) because the
node admits on the control plane's session view, which does not re-validate the analyst's token.

**Impact.** Platform pauses within an hour. This is Microsoft's outage; there is nothing to fix
here. There is deliberately no local credential store to fall back to (CLAUDE.md "no separate
password store").

**Act.** Confirm on the Microsoft 365 service health dashboard; tell analysts the panel will show
Browsing stopped at lease expiry and that nothing has leaked. Do not relax Conditional Access or
device-compliance requirements to restore service (CLAUDE.md "decisions you must not make
silently").

**Verify.** Sessions issuing again once Entra recovers. Nothing to clean up.

**Audit gap.** None. Sessions that lapsed are recorded as `session_expired`/`session_revoked` by the
expiry sweep like any other.

---

## 5. Key Vault or audit-anchor storage unreachable

**Symptoms.** Key Vault: session issuance and renewal fail (`mina_session_establish_failures_total`
rising, reason naming the CA), because every session certificate is signed by the vault's key —
there is no local copy of it (D-18, D-20). Anchor storage: export failures and
`AuditAnchorException` in the API log, and `/api/audit/verify` `anchorsChecked` stops growing.

**Impact.** Key Vault: new sessions and renewals stop; existing tunnels run to lease expiry. Anchor
storage: no analyst impact; the local chain keeps being written and verified, but new events are not
yet anchored in write-once storage, so for the window the chain's tamper evidence is weaker.

**Diagnose.** Azure service health for Key Vault / Storage in the region. From the app host, the
Arc managed identity obtaining a token (runbook 6) is the other half of this path — a Key Vault
outage and an Arc failure look identical from the API's log until you check which.
`mina-ca show --vault <key_vault_uri>` from an operator workstation separates them: green means the
vault is fine and the host's identity is the problem.

**Act.** Wait for the Azure service, or fix Arc. Do not re-root the CA on a local key to restore
issuance: that would mint a trust root nobody controls (the exact failure `mina-ca` exists to make
impossible — see its header).

**Verify.** Issuance resumes. For anchors: the export background service catches up on its own
(one lease holder exports every interval); confirm `anchorsChecked` advances and `anchorProblems`
is empty. A chain that ends *below* its anchors — only possible after a database restore — raises
`AuditAnchorException` and is runbook 7's problem, not this one's.

**Audit gap.** The chain itself has none. Record the window in which events existed unanchored.

---

## 6. Arc agent failure on a control-plane host

**Symptoms.** On the app host, both SQL (`Authentication=Active Directory Default`) and Key Vault
fail at once with token-acquisition errors: `/healthz` 500, issuance stopped, audit writes failing
(so governance actions fail closed). On the SQL host, the SQL service's Entra federation stops
validating the app's logins. There is no stored credential to fall back on, by design (D-17,
SR-005): this failure mode is the price of that property and is accepted.

**Diagnose.** On the host (guest agent exec): `azcmagent show` and `azcmagent check`. Common
causes: the agent's token endpoint (`localhost:40342`) not answering, clock skew, the machine's
Arc resource deleted or disconnected in Azure, or the "Hybrid agent extension applications" group
membership for `NT SERVICE\MSSQLSERVER` lost on the SQL host (M4-18 describes the exact wiring).

**Act.** `azcmagent connect` again with an operator's Azure credentials if the resource is gone
(this changes the machine's identity: re-grant Key Vault Crypto User / Secrets User to the new
principal via `control_plane_principal_id` in `environments/dev`, and `CREATE LOGIN ... FROM EXTERNAL
PROVIDER` again in SQL `master`). Otherwise restart `himds` and the agent, and re-check.

**Verify.** `/healthz` 200 on both listeners; `mina-ca show` from the host's own identity is not
possible, so confirm issuance by starting a lab session. `/api/audit/verify` intact.

**Audit gap.** None: actions that could not be audited did not happen.

---

## 7. SQL Server failure, backup and restore

**What the database holds.** `Sessions`, `SensitiveSessionRequests`, `RegionChangeRequests`,
`AuditEvents` (the hash-chained C1/C2 trail), `Hostnames` and `SuppressedTraffic` (C3), and
`BackgroundLeases`. Everything governance-relevant lives here; the anchors in Azure immutable
storage are what prove it has not been rewritten.

### Backup

`scripts/sql-backup-onprem.ps1` runs **on the SQL host** as a scheduled task under the SQL service's
Windows identity (no SQL login exists; the instance is Windows-authentication-only). It takes
`-Type Full` nightly and `-Type Log` every 15 minutes (the database must be in FULL recovery for
log backups; the script checks and refuses otherwise), `WITH CHECKSUM, COMPRESSION`, runs
`RESTORE VERIFYONLY` on every file it writes, prunes by `-RetainDays`, and appends one JSON line per
backup to a manifest. The backup directory is the organisation's to place on storage with its own off-host
copy; the script does not copy off the host itself.

Recovery point objective with that cadence: 15 minutes of governance events. Whether that is
acceptable is the owner's call (OPERATIONS.md SLOs); tightening it is a schedule change, not code.

### Restore

1. Stop the application first (both IIS app pools on the app host), or the API will write new
   events on top of a chain you are about to replace.
2. Restore to the production name with `scripts/sql-restore-drill-onprem.ps1 -TargetDatabase Mina
   -Replace` — the same script the drill uses, pointed at the real name. It restores the latest
   full plus every later log in the manifest, runs `DBCC CHECKDB`, and prints the row count and
   maximum `Sequence` of `AuditEvents`.
3. **Compare that maximum sequence with the anchors.** The anchors in the immutable container
   record ranges of the chain that existed. If the restored chain ends below the last anchor, the
   API will refuse to export (`AuditAnchorException`) and `/api/audit/verify` will report the
   missing range in `anchorProblems`. That is the system telling you how much governance history
   the restore lost. Record it; it is a finding, not a condition to clear.
4. Start the application. Run `/api/audit/verify`.

**Then stop and escalate.** Restoring the audit database is listed as a recovery action, and it is
also, from the chain's point of view, indistinguishable from the tampering the anchors exist to
detect (PHASE0_DECISIONS D-10a notes this unresolved tension). The owner decides whether the lost
range is accepted or whether the incident becomes a security investigation. Do not try to "fill"
the gap: there is no supported way to write audit events by hand, and inventing one would be the
breach.

### Drill

`scripts/sql-restore-drill-onprem.ps1` with no `-Replace` restores to `Mina_RestoreDrill`, checks
it, prints the figures, and drops it (keep with `-Keep`). Run it monthly from the scheduled task's
identity and file the output. A drill that has never been run is a backup that has never been
proven.

---

## 8. Proxmox host or cluster failure; control-plane host rebuild

One of each host today (M4-15); HA is M4-22's and the organisation's infrastructure team's. Until then, a
Proxmox node failure is a control-plane outage (runbook 3) and recovery is a rebuild.

**Rebuild from `environments/dev-onprem`.** All three hosts are Terraform resources:

| Host | Resource address | State it holds |
|---|---|---|
| proxy | `module.control_plane.proxmox_virtual_environment_vm.proxy` | none; cloud-init owns everything |
| app | `module.app_server.proxmox_virtual_environment_vm.app` | the Data Protection key ring (`Mina:Hosting:DataProtectionKeyPath`) — back it up; losing it invalidates the UI's cookies and nothing else |
| sql | `module.sql_server.proxmox_virtual_environment_vm.sql` | the database (runbook 7) |

`terraform plan -replace=<address>` then `apply` recreates the host. A replace of the proxy is
destructive and quick (minutes; the node endpoint is down for the rebuild — runbook 2's symptoms).
The Windows hosts come back as fresh clones and need the post-clone steps again: Arc onboarding
(runbook 6 covers the identity consequences), SQL Server configuration and the Entra federation
registry wiring (M4-18), then the deploy scripts for the API and UI. These are scripted in
`scripts/` where they have been automated and documented in the backlog rows where they have not;
budget hours, not minutes, for a Windows host.

**Drill.** Rebuild the proxy in the dev environment quarterly — it is the cheapest host and the
one whose loss is visible to every node. The success criterion is runbook 2's verify step.

**Audit gap.** A proxy or app rebuild creates none. A SQL rebuild is runbook 7.

---

## 9. Suspected egress-node compromise

**Symptoms.** Wazuh `sensitive_suppression_mismatch` (a node sending destinations for a suppressed
session — threat N5), `telemetry_region_mismatch` or `telemetry_unattributable` from one node,
proxy rule 100610 (node-API traffic from outside the stamps' NAT prefixes), unexpected `KeySign`
volume on the CA key (M4-24 Log Analytics alert), or anything from EDR on the VMSS.

**Impact.** A compromised node can see the plaintext CONNECT targets of the tunnels it carries
(hostnames only; TLS inside the tunnel is end to end) and could try to reach the control plane as
a node. It cannot reach corporate networks (NSG `out_deny_corp`, nftables on the node) or issue
sessions (node role only). It cannot read other regions (per-region grant).

**Act, in this order — contain, then preserve, then rebuild.**
1. **Contain.** Remove the instance from the load balancer backend pool, or deallocate it. Do not
   reimage yet: that destroys evidence. If the whole stamp is suspect, disable the region
   (runbook 15).
2. **Revoke its identity's access.** Remove the `Mina.Node.<region>` app-role assignment from the
   stamp's managed identity (`vmss_principal_id`); the control plane refuses the node on the next
   request. Every node in the stamp shares that identity, so this takes the stamp off the air —
   which is the right trade.
3. **Preserve.** Snapshot the instance's OS disk to a storage account the incident team controls.
   The node's Envoy access log (`/var/log/mina/envoy-access.log`) is on that disk and is the
   record of what the node carried; so is the journal.
4. **Rebuild.** Reimage the instance (or the set). Re-assign the app role. Rotate nothing else by
   default: node certificates are issued per boot from a CSR the node generates, and the CA key
   never left Key Vault — but if there is any indication the node reached the vault, run the CA
   rollover (OPERATIONS.md, M4-2).
5. **Review the telemetry.** Browsing data for sessions the node served in the window
   (management console, Browsing Data, Telemetry viewer role) tells you which analysts' destinations
   were exposed to the attacker. Those analysts are informed per the incident process.

**Verify.** The stamp healthy with fresh instances; no further mismatch events; `/api/audit/verify`
intact and anchored.

**Audit gap.** None on the control plane. The node's own log is evidence, not audit.

---

## 10. Endpoint agent or profile malfunction

The agent fails closed on its own: no agent, no route out for the research browser, and the
firewall rule persists independently of the agent (USER_MANUAL 6.6). The diagnostic path is
OPERATIONS.md "New Windows endpoint onboarding" step 6 and USER_MANUAL 4.7; Intune detection
reinstalls a package whose rule has gone. Nothing here touches the control plane. Tamper indicators
reaching Wazuh (`client_tamper_suspected`, rule 100530 clustering) are a security event, not a
support ticket: treat a device with repeated indicators as suspect and have it re-imaged.

---

## 11. Wazuh integration failure

**Symptoms.** No Mina events arriving at the Wazuh manager; the delivery file at
`Mina:Wazuh:Delivery:EventFilePath` not growing (the API's `WazuhDeliveryBackgroundService` has
stopped writing), or growing without the agent shipping it.

**Impact.** Detection delayed. **Nothing is lost:** events are in the audit chain; delivery is a
read-behind of the chain (M3-5, `WazuhDeliveryBackgroundService`), so when it recovers it resumes
from where it stopped. This is why the chain, not Wazuh, is the record.

**Diagnose.** Is the API's delivery service writing (the file's mtime)? Is the Wazuh agent on that
host running and is `ossec.conf`'s `<localfile>` pointing at the same path (integrations/wazuh/README)?
Is the manager reachable from the DMZ (the narrow flow ADR-0006 permits)?

**Act.** Fix the broken hop. Do not disable delivery to stop the alerts.

**Verify.** Events for a test action (start and end a lab session) appear in Wazuh with the right
rule id. **Audit gap.** None.

---

## 12. SigNoz integration failure

**Symptoms.** Metrics stop in SigNoz; the API log shows OTLP exporter errors. The proxy host's
collector (`otelcol-contrib`) failing shows as the proxy's metrics and logs stopping while the
API's continue, or vice versa.

**Impact.** Operational visibility only. Nothing governance-relevant goes to SigNoz, by design
(AC-014: hostnames never reach it; the scrubbers enforce that and `mina_telemetry_scrub_drops_total`
counts attempts).

**Act.** Confirm `Mina:Observability:OtlpEndpoint` and the proxy's `otlp_endpoint` point at a
reachable collector; `systemctl status otelcol-contrib` on the proxy. **Never** disable the scrub
processors to "see more" (integrations/signoz/README, "the one rule").

**Verify.** Metrics flowing. **Audit gap.** None.

---

## 13. Published-endpoint TLS certificate renewal

With the Cloudflare Tunnel shape (M4-14 as built), public TLS terminates at Cloudflare's edge with
a certificate Cloudflare issues and renews; the proxy VM speaks plain HTTP to the connector only.
There is nothing to renew on the proxy. Check the edge certificate's expiry in the Cloudflare
dashboard as part of the monthly review, and alert on it externally (any uptime monitor that
reports certificate expiry, pointed at `https://<public_hostname>/healthz`).

If the deployment ever terminates TLS on the proxy itself (`tunnel_connector_cidr = 0.0.0.0/0`
variant), this runbook needs writing properly: a certbot timer, a renewal hook that reloads nginx,
and the proxy's access log confirming the new chain. Do not deploy that variant without it.

---

## 14. Egress region activation

D-11: one active production region at launch; a second is stood up on demand (M4-1 drill). Regions
are approved by the owner (`Mina:Regions:Approved`, D-08), made active by configuration, and the
console's region administration (ADR-0008 Option C) records the request-and-apply trail; the
actual change is still IaC plus the deploy script, deliberately.

1. `environments/dev` (or the production equivalent): add the stamp module instance for the new
   region, `terraform plan`, review, `apply`. Note `ingress_public_ip` and `egress_ip_prefix`.
2. Assign `Mina.Node.<region>` to the new stamp's `vmss_principal_id` (entra-node-roles.tf).
3. Add the region's NAT prefix to the proxy's `node_source_cidrs` in `dev-onprem` and apply, or
   the proxy will tag every request from the new stamp as an unknown source (Wazuh 100610).
   Do this **before** step 4 if `enforce_node_source_cidrs` is on, or the new nodes are refused.
4. Deploy script with `-EgressRegion <region> -EgressHost <ingress ip> -EgressServerName <name>`,
   then `-ApprovedRegions`/`-ActiveRegions` as the full lists. Analysts see the region on their
   next panel refresh.
5. Verify: a lab session in the new region; its node's telemetry recorded; the public egress IP
   seen by an echo canary inside `egress_ip_prefix` (AC-003).

---

## 15. Emergency disable of an egress region

1. Remove the region from `Mina:Regions:Active` via the deploy script's `-ActiveRegions` (the full
   remaining list). New sessions can no longer select it; existing sessions in it stop being
   renewable at their next renewal.
2. If the stamp must stop *now*: remove the backend pool members or stop the VMSS in Azure. Every
   node then refuses new tunnels immediately and open tunnels die with the process. Nothing falls
   back (fail closed).
3. Record it: there is no audit event for a configuration change made by deployment, so write the
   change, the reason and the operator into the incident ticket and, if the console's region
   administration was used, let its request trail be the record.

Re-enabling is runbook 14 from step 4.

---

## 16. Certificate, key and secret rotation

| What | How often | Procedure |
|---|---|---|
| Internal CA (signing key + certificate) | Before expiry; `mina-ca rotation-check` warns and the audit chain carries `ca_rotation_status` (Wazuh 100531) | OPERATIONS.md "Internal CA rollover (M4-2)" |
| Session client certificates | Every lease (≈60 min), automatically | nothing to do |
| Node server certificates | Every node boot, from a node-generated CSR | reimage the node to rotate |
| Public TLS at the edge | Cloudflare-managed | runbook 13 |
| Proxmox API token (Terraform) | Per organisational policy | rotate in Proxmox, update the environment variable; it is in no file and no state |
| Data Protection key ring (UI cookies) | Automatic (ASP.NET Core, 90 days) | back up the directory with the app host |
| Wazuh agent key, SigNoz ingestion key (if any) | Per those products' policy | their runbooks |

There are no client secrets anywhere in the product (ARCHITECTURE §4): the API is a resource
server, the UI uses the tenant's OIDC flow, the app host and nodes use managed identities. A
rotation that seems to need a secret value is a sign something was deployed outside the design.

---

## 17. Database schema migration

Migrations are applied as a deliberate deployment step with an idempotent script; the application
never migrates on startup (Persistence README). Generate with `dotnet ef migrations script
--idempotent`, review the SQL (it must be additive — no `DROP` of a governance table or column
without an ADR), take a full backup (runbook 7) immediately before, apply with the operator's
Windows identity through the guest agent, then deploy the matching application build. Order
matters: new schema first, then new code, because the code assumes the schema and the schema
tolerates the old code only when the migration is additive.

Rollback of a migration is `dotnet ef migrations script <to> <from> --idempotent` reviewed the
same way, and only after the application has been rolled back to the build that matches `<to>`
(runbook 18). Data added by the newer build in new columns is lost by a down migration; that is
why migrations are kept additive.

---

## 18. Rollback to the previous release

The deploy scripts (`scripts/deploy-control-plane-api-windows.ps1`,
`scripts/deploy-management-ui-windows.ps1`) are clean-slate and idempotent: a rollback is a
deployment of the previous git ref with the same parameters.

1. Identify the last known-good commit (the deploy script records the publish it made in its
   output; keep those logs). `git checkout <ref>`.
2. If the release being rolled back included a migration, decide first whether the schema stays
   (preferred — additive migrations tolerate the older code) or is reverted (runbook 17).
3. Run the deploy script for the API, then the UI, with the same parameters as the forward deploy.
   The scripts stop the app pool, replace the content, reconcile IIS bindings and firewall rules,
   and verify `/healthz` and the listener separation before reporting success.
4. Node sidecar: the stamp pins a sidecar artifact by URL and checksum (M4-29); rolling the node
   back is pointing cloud-init at the previous artifact and reimaging. The endpoint package rolls
   back through Intune's own supersedence (OPERATIONS.md onboarding section for its cadence).

**Verify.** Both `/healthz` 200; a lab session; `/api/audit/verify` intact and anchored.

---

## 19. Break-glass activation and post-use review

The Azure half (emergency-access accounts, PIM-gated RBAC group) is M4-5. The on-premises half is
drafted in OPERATIONS.md ("Break-glass activation (on-premises plane, D-10a)") and is **PROPOSED,
not ratified**. Until the owner ratifies it, there is no approved break-glass procedure for the
on-premises plane, and this file will not pretend otherwise.

---

## Backup and restore summary

| Asset | Where | Protection | Backup | Restore |
|---|---|---|---|---|
| Control-plane database | SQL Server on `mina-*-cp-sql` | host backup; `scripts/sql-backup-onprem.ps1` (full nightly, log every 15 min, checksum + verify) | the script's manifest and files | runbook 7, `scripts/sql-restore-drill-onprem.ps1 -Replace` |
| Audit anchors | Azure immutable blob container | immutability policy (must be `Locked` in production — a production gate) | none needed: write-once; the chain is the mutable copy | none; they are the reference the chain is checked against |
| CA signing key | Azure Key Vault `mina-internal-ca` (EC P-256) | soft delete + purge protection (Terraform) | `scripts/backup-keyvault-ca.sh` — `az keyvault key backup` and `secret backup` of the CA certificate; the blob is restorable only into a vault in the same subscription and geography, by design | `az keyvault key restore` / `secret restore` into a replacement vault, then re-point `Mina:Pki:KeyVaultUri`; if the key is gone beyond recovery, this is a CA rollover (OPERATIONS.md M4-2), not a restore |
| Terraform state | Azure Storage (dev, dev-onprem keys) | access-controlled (threat N6); enable blob versioning on the account | versioning | restore the previous version of the state blob |
| Data Protection key ring | app host, `Mina:Hosting:DataProtectionKeyPath` | file system | with the host | copy back; or accept that every UI user signs in again |
| Egress stamps | Azure, `modules/egress-stamp` | none needed | IaC | `terraform apply` (drill below) |
| Proxy host | Proxmox | none needed | IaC + cloud-init | runbook 8 |

## Drills

| Drill | Cadence | Script / procedure | Pass criterion |
|---|---|---|---|
| SQL restore | monthly | `scripts/sql-restore-drill-onprem.ps1` | `DBCC CHECKDB` clean; `AuditEvents` max sequence within RPO of production's current sequence |
| Stamp rebuild | quarterly, dev | `scripts/drill-stamp-rebuild.sh` (plan, explicit confirmation, apply, then an mTLS handshake probe against the new ingress) | handshake demands a client certificate (AC-016 still holds); a lab session tunnels; telemetry recorded |
| Proxy rebuild | quarterly, dev | runbook 8, `terraform apply -replace=module.control_plane.proxmox_virtual_environment_vm.proxy` | runbook 2's verify step within 15 minutes |
| Region activation | before the second region is ever needed for real (M4-1) | runbook 14 end to end in dev | AC-003 echo inside the new `egress_ip_prefix` |
| Rollback | with every release candidate, in dev | runbook 18 against the previous tag | both `/healthz` 200, verify intact |
| CA rollover | annually, dev | OPERATIONS.md M4-2 | every agent on the new trust root; `mina-ca rotation-check` green |

Drill results are filed with the release evidence (AC-019). A drill not run on schedule is reported
in the on-call handover, not quietly skipped.
