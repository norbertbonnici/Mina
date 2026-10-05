# ADR-0008: Region administration — read-only visibility now, write path deferred

- Status: **Accepted 2026-09-11** — Option C chosen by the owner directly and implemented the same day
- Date: 2026-09-10 (proposed), 2026-09-11 (decided)
- Decision owners: platform owner (norbert@bonnici.mt) — decided directly, not inferred
- Related: backlog M3-2 ("region administration" remaining item), D-08 (administrator-approved
  region list), ARCHITECTURE §8, `docs/OPERATIONS.md` ("Egress region activation" / "Emergency
  disable of an egress region" runbooks, both still required but not yet written), EVENT_SCHEMAS.md
  (`policy_changed`, catalogued 2026-08 and not yet emitted by anything)

## Context

M3-2's own remaining-work note names "region administration (configuration today)" as unbuilt.
Today, which regions are approved (D-08) and which of those are active/selectable
(`RegionPolicy.SelectableRegions`, AC-008) is set entirely by `Mina:Regions:Approved:*` /
`Mina:Regions:Active:*` configuration, written by `deploy-control-plane-api-windows.ps1`'s
`-ApprovedRegions`/`-ActiveRegions` parameters (and, since 2026-09-10, mirrored onto
`deploy-management-ui-windows.ps1`) into each deployment's `web.config`. `RegionPolicy` reads this
once at process startup; there is no runtime write path anywhere in the platform.

CLAUDE.md lists **"changing the approved production region/public-IP strategy"** as a decision
that must never be made silently, requiring explicit human approval. That line was written about
the *initial* strategy choice, but its reasoning applies identically to *any* live change to which
regions are approved or active: this list controls where every analyst's research traffic is
permitted to exit to, and the current mechanism (a reviewed deploy-script invocation, itself IaC
per CLAUDE.md's own "infrastructure must be reproducible as code" principle) is what makes every
such change reviewable, attributable to a commit or a deploy log, and reversible by redeploying a
known-good parameter set. A form field in a web admin screen that writes this list at runtime would
remove all three properties unless something replaces them — and nothing does yet.

This is the same shape of question D-10a (break-glass) and ADR-0007 (background traffic) were
written up rather than silently decided: a plausible, useful feature whose implementation choice is
itself a governance decision, not only an engineering one.

## Decision

**Option C, decided by the owner directly 2026-09-11 and built the same day.** Reasoning for the
choice over B: region activation is not actually gated by a config flag, it is gated by standing up
real Azure infrastructure (Terraform, VMSS, the node's own certificate SAN via M2-2d) — Option B's
database would become a second source of truth that still has to agree with IaC at deploy time,
without removing the actual bottleneck. Option B also implicitly needs a dual-control approval
model this ADR would otherwise have had to invent as a side effect, rather than as its own
considered decision. Option C avoids both: IaC stays the sole authoritative mechanism, and the
workflow captures intent and its audit trail without inventing new authority.

**What Option C means concretely, and what was built:** a `RegionChangeRequest` aggregate
(`control-plane/src/Mina.ControlPlane.Domain/Regions/`) records who asked for what
(add/remove/activate/deactivate a region) and why; an admin later calls `MarkApplied` to confirm the
reviewed deploy actually happened (or `Dismiss` to decline it) — deliberately not restricted to "not
the requester" the way `SensitiveSessionRequest.Approve` is, since there is no second-party
authorization to protect here, the deploy script is what actually authorizes anything. New
`/region-requests` screen (`Mina.Admin`-gated, matching this ADR's own reasoning that region
governance is an admin concern), linked from Overview's existing region table. `MarkApplied` writes
`policy_changed` at High severity — catalogued in EVENT_SCHEMAS since before this had a real
producer. Full detail: `docs/BACKLOG.md` M3-2, `docs/PHASE0_DECISIONS.md` D-23.

Option A (read-only visibility, no request capture) shipped first, 2026-09-10, as the
uncontroversial floor while this decision was pending — it is subsumed by Option C, not replaced:
the region table Option A added to is still exactly what Option C's screen links from.

## Alternatives considered

### Option A — Read-only visibility, point at the existing IaC path (**implemented**)

No new write mechanism. The UI shows current state; changing it stays a deploy-script invocation,
same as today.

- **Pros:** Zero new trust surface, zero new governance question to answer, costs almost nothing,
  and closes the honest half of what "administration" without a write path can mean — a viewer can
  now find out *how* to request a change instead of looking for a button that was never going to be
  safe to ship without more design.
- **Cons:** Does not give an admin self-service ability to change regions without engineering
  involvement, which is presumably what "region administration UI" was actually asking for.

### Option B — Persisted, UI-editable region configuration with its own approval workflow

A new `RegionConfiguration` aggregate (approved/active lists, versioned), an admin screen to
propose a change, and an approval step before it takes effect — deliberately mirroring
`SensitiveSessionRequest`'s request/approve/deny shape rather than a plain CRUD form, since a region
change is at least as consequential as a sensitive-session suppression and today has *no* approval
concept at all. `RegionPolicy` would read from this store instead of static `IOptions`, and every
change would emit the already-catalogued `policy_changed` event (currently emitted by nothing).

- **Pros:** Real self-service admin capability; the feature M3-2's note most plausibly meant;
  finally gives `policy_changed` a producer.
- **Cons:** Real, non-trivial scope: a new aggregate and migration, a decision on whether one
  Mina.Admin's approval is enough or whether region changes need the same dual-control break-glass
  reasoning already applies to, a decision on how a live DB-driven policy interacts with the IaC
  config that still has to agree with it at deploy time (which wins on conflict — the database or
  the file?), and a decision on whether a node's own TLS certificate SAN issuance (tied to
  `Mina:Egress:Regions:<name>`, M2-2d) needs to move in lockstep with an admin-driven activation or
  stays a separate, slower, cert-issuing step regardless of what the database says is "active".
  None of these are engineering-only questions.
- **Verdict:** the actual feature, but not something to build unattended overnight without the
  owner having chosen an approval model first — exactly the CLAUDE.md stop condition this ADR
  exists to respect.

### Option C — UI captures a change *request*, a human still applies it via the reviewed script (**chosen**)

Middle ground: an admin submits a proposed region-list change with a justification (mirroring
`SensitiveSessionRequest`'s justification-reference pattern), which is recorded and visible, but
the actual `Mina:Regions:*` values still only change via a reviewed `deploy-*-windows.ps1` run — the
UI captures *intent*, not *authority*.

- **Pros:** Keeps IaC as the sole authoritative mechanism (no new consistency question between a
  database and `web.config`), while giving admins a real, audited way to ask for a change instead
  of an out-of-band conversation. Lower engineering risk than Option B — no new "who can approve
  this" model to invent, since the existing human-reviewed deploy step already is that model.
- **Cons:** Still not self-service; an admin's request still waits on an operator running a script.
  Some of Option B's value without most of its risk, but also without most of its payoff.

## Security/privacy consequences

No data collection change either way. Option A changes nothing about who can affect region
approval — the deploy scripts already required whoever runs them to hold the Graph/Proxmox
credentials this whole pipeline needs. Options B and C would each introduce a new answer to "who
can change where research traffic is permitted to exit, and how is that recorded" that does not
exist today in any form — currently the only record of a region change is a git commit and a deploy
log, which is adequate for an IaC-only mechanism and would not be adequate on its own for a
database-editable one.

## Operational consequences

Option A: none — a documentation/UI-text change only, alongside this ADR. Options B/C, if chosen,
would need: a migration (Persistence), a decision on the two required runbooks `OPERATIONS.md`
still lists as missing ("Egress region activation", "Emergency disable of an egress region") — both
of which should probably be written *against* whichever option is chosen, not before, since the
runbook is different depending on whether "disable a region" is a script run or a UI action — and
resolution of the IaC/database consistency question named under Option B before it could ship.

## Approval

**Approved — Option C, decided directly by the owner 2026-09-11** ("decide the region
administration write path"), not inferred from context. Option A needed no separate approval, being
a documentation/visibility change only. Option B remains rejected for the reasons above, recorded so
a future "just add an edit button" suggestion has this reasoning to weigh against. Recorded as D-23
in `docs/PHASE0_DECISIONS.md`.
