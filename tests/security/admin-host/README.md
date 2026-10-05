# tests/security/admin-host

The D-21 enforcement check. Admin-only PowerShell that reads the credential-store ACLs and the
CI-agent inventory **of the machine it runs on**, mutates nothing, and carries its own negative
controls.

D-21 decides that administration hosts do not run third-party CI. THREAT_MODEL B10 records why:
such a host sits inside every Mina plane at once — the SSH key that is `root` on the Proxmox host,
an Azure session for the subscription holding the CA signing key and the audit anchors, and the
Terraform state credentials. Backlog M4-30(b) asks for a check that **enforces** that rather than
trusting it.

```powershell
.\Invoke-AdminHostExposureProbe.ps1                    # verdict object; add -ReportPath for JSON
.\Test-AdminHostProbeSelfTest.ps1                      # the harness alone
```

| File | What it is |
|---|---|
| `MinaAdminHostProbe.psm1` | The predicates. The probe and every self-test leg call **these** functions — a self-test that exercised a reimplementation would prove nothing about what runs. |
| `Invoke-AdminHostExposureProbe.ps1` | The probe: gate, stores, CI agents, host principals, gaps, verdict. |
| `Test-AdminHostProbeSelfTest.ps1` | 16 legs proving the predicates can fail. Runs automatically unless `-SkipSelfTest`. |

## Why a naive version of this check would have passed the incident

The ACE that caused this finding named a local **group** (`GITHUB_ActionsRunner_*`) whose member
was `NETWORK SERVICE`. A check that compares ACL identity strings sees an unfamiliar group name,
has no rule for it, and reports clean — on the exact configuration that exposed the hypervisor
key. So the ACL predicate:

- **closes group membership to leaf principals**, and names the leaf in the finding, not the group;
- **compares SIDs, never names** — names are localised, and a *domain* group called `Administrators`
  renders as `DOMAIN\Administrators`, which substring matching wrongly accepts;
- **treats a closure it cannot complete as a failure**, never a skip. The incident's group is
  precisely the thing you must be able to close, so "could not close" must not read as "nothing
  there";
- **evaluates ACEs in stored order, deny-aware.** "Is there an Allow ACE?" is wrong in both
  directions: it fails a safe canonical `(D;;FA)(A;;FA)` and, worse, passes an unsafe
  non-canonical `(A;;FA)(D;;FA)`;
- **hard-fails a null DACL.** `Get-Acl`'s `.Access` collection is *empty* there, so an ACE loop
  reports clean on the most open object possible.

`icacls /findsid` is not used: on this host it returns "No files with a matching SID was found"
for SIDs that are plainly on the ACL. A check built on it reports clean forever and looks like it ran.

## The expected result here is VIOLATION

On `ADMIN-WS01` today this reports **VIOLATION**, because the unrelated CI runner is still installed
(M4-30 remaining item (a)). **A green run on this host would mean the check is broken, not that the
host is clean.** When that runner moves, the synthetic self-test legs become the only proof the
predicates still work — they must never be deleted as scaffolding.

Verdict ladder, highest precedence first: `SELF-TEST-FAILED` (4) · `VIOLATION` (1) ·
`INCONCLUSIVE` (2) · `NOT-AN-ADMINISTRATION-HOST` (3) · `COMPLIANT` (0). Self-test failure outranks
a violation deliberately — a predicate that gets a control leg wrong may also be producing findings
for the wrong reason, and remediating a fixture bug is worse than an open finding.

The gate is a positive control: a host that produces no evidence of holding Mina credentials
reports `NOT-AN-ADMINISTRATION-HOST`, which is a scope statement, **not** a pass. Enumeration
floors work the same way — a `COMPLIANT` with zero DACLs evaluated is the failure this check exists
to prevent.

## Do not run this in CI

`.github/workflows/ci.yml` uses GitHub-hosted runners, which have no `.azure`, no `.ssh` and no
installer group. The probe would emit a clean, meaningless result about a machine nobody asked
about. And it must never run on a *self-hosted* runner: it would then execute under the very
identity it exists to flag. Run it by hand on an administration host — before assembling a release
evidence bundle, and after any software installation or agent enrolment.

## What it cannot see

Written down because a `COMPLIANT` will otherwise be read as more than it is.

- **It proves nothing about the past.** A workflow that read `.azure` while the runner group held
  FullControl over the profile left no trace this check can see, and those tokens stay valid until
  they expire or are revoked. Clean today ≠ never exfiltrated.
- **Stopped WSL distros are not enumerated**, because enumerating one starts it, and that is a host
  change the probe may not make silently. A Linux agent inside one reads `/mnt/c/Users/<profile>/.ssh`
  directly and matches no Windows signature. Reported as a GAP forcing `INCONCLUSIVE` — an operator
  who learns to read `INCONCLUSIVE` as noise has re-created the blind spot by habit.
- **Containers cannot be enumerated when the engine is down**, which is how Docker Desktop presents
  here. An agent container with `restart: always` becomes operational the moment it starts.
- **`SeImpersonatePrivilege` is held by `NETWORK SERVICE` and `LOCAL SERVICE` by Windows default**,
  which is a documented path from any local service account to SYSTEM — and SYSTEM is necessarily
  accepted. So a clean ACL result on a host still running a local CI agent is arithmetically true
  and practically worthless. **No ACL configuration can contain a local CI agent; only removing it
  can.** If anyone ever "fixes" a violation by tightening ACLs instead, every store will go on
  reporting CLEAN.
- **`BUILTIN\Administrators` is accepted** because it holds SeTakeOwnership/SeBackup/SeDebug and can
  read anything regardless of the DACL — denying it is unenforceable. Adding an account to
  Administrators therefore reproduces the incident with every store DACL still clean. The membership
  list is reported so that change is visible.
- **Domain groups cannot be closed without AD**, so they are reported as incomplete — correct, but
  it means hand-resolution, and hand-resolution is where an exemption gets added that later hides
  something real.
- **The store list can never be complete.** It is a base list plus known repo credential files;
  a secret in an application's private format or in the registry will not match. `set-proxmox-env.ps1`
  (plaintext Proxmox token, gitignored) is on the list only because the incident review found it.
- **It is a point-in-time snapshot with no schedule.** The window between an installer running with
  reasonable defaults and the next manual run is unbounded — and that window is exactly the
  mechanism D-21 exists to defend against.
- **It enforces D-21, which is not the answer to B10.** A fully `COMPLIANT` result still describes a
  machine holding SSH root on the hypervisor, a live Azure session for the CA subscription, and the
  Terraform state credential under one interactive login. That is M4-30 item (c), still open.
