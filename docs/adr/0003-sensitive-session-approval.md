# ADR-0003: Manager-approved sensitive sessions

- Status: **Accepted 2026-08-31** (workflow + expiry-terminates default confirmed, D-06)
- Date: 2026-08-31
- Related: ADR-0002, `docs/ARCHITECTURE.md` §7, `docs/LOGGING_AND_PRIVACY.md`

## Context

Analysts performing highly sensitive research require an approved way to suppress URL telemetry
without removing accountability for session use. Suppression must be authoritative in the
control/logging plane — never an analyst-controlled client toggle.

## Proposed decision

Implement a time-bound manager approval workflow with **server-side suppression enforcement**:

1. Analyst submits a request (justification, requested duration) from the agent UI or
   management UI. Requests may reference a case/justification number, not case content.
2. A user holding the Approver role — who is not the requester — approves or denies in the
   management UI. Self-approval is rejected by the control plane, not just hidden in the UI.
3. Approval carries an explicit TTL. Maximum duration is a configurable policy value.
4. On activation, the control plane marks the session suppressed and pushes the flag to the
   egress node(s). Under the recommended ADR-0002 Option 1, suppression is entirely
   server-side: nodes stop recording hostnames for that session and instead emit
   suppression-active markers and aggregate counters. If browser-originated telemetry (Option 2)
   is ever adopted, enforcement is **dual**: the client is instructed to stop *and* the
   control plane drops anything that still arrives — client cooperation is never relied upon.
5. The analyst's UI clearly indicates the current logging mode (FR-006); the indicator is
   advisory only and has no enforcement role.
6. **Expiry terminates the session** (proposed default): at TTL expiry the control plane stops
   renewing the session credential and instructs the egress node to drop it. The analyst may
   start a fresh normal session immediately. Rationale: silently reverting to full logging
   mid-session could capture a continuation of the sensitive activity the approval was meant to
   protect; a hard boundary is safer and simpler to audit. (FR-011 permits either behaviour;
   the alternative — revert-with-prominent-warning — is noted for the human review.)

## State machine

`NORMAL -> REQUESTED -> APPROVED -> ACTIVE_SUPPRESSED -> EXPIRED/ENDED -> NORMAL`, with
`REQUESTED -> DENIED -> NORMAL` and `REQUESTED/APPROVED -> CANCELLED -> NORMAL`. Every
transition is a control-plane operation, audited, and forwarded to Wazuh. The analyst cannot
transition into `ACTIVE_SUPPRESSED` directly; activation requires an existing `APPROVED`
record for that analyst, device and time window.

## Retained during suppression (mandatory, non-configurable)

User identity; managed device identity; session ID, start/end; selected egress region; request
and justification reference; approver and decision; approval/expiry timestamps; administrative
and break-glass events; aggregate traffic counters. Permanent exemptions are prohibited.

## Consequences

- Requires the management UI/API role model (Analyst / Approver / Platform Admin) and the
  session state machine in the control plane.
- Requires node-side per-session logging flags and an expiry scheduler with clock-skew care.
- Approver actions are themselves high-value audit events (approver collusion appears in the
  threat model; mitigated by auditing, no self-approval, and periodic review reports).

## Approval

**Amended by the project owner 2026-09-01 (D-06a): termination applies only to an approval that was
actually activated.** A request that was approved and never activated lapses on its own; the
analyst's session, which was never suppressed, continues under normal logging. The expiry event is
written either way and records whether a session was terminated.

**Confirmed by the project owner 2026-08-31 (D-06): expiry terminates the session.** The
revert-with-warning alternative was considered and rejected in that decision round. Recorded in
`docs/PHASE0_DECISIONS.md`.
