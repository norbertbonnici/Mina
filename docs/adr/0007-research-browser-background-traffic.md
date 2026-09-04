# ADR-0007: Research-browser background traffic in hostname telemetry

- Status: **Proposed 2026-09-04** — awaiting owner and DPO decision
- Date: 2026-09-04
- Decision owners: FIAU platform owner, security architecture, data protection
- Related: ADR-0002 (hostname telemetry), ADR-0001 (C2 enforcement), `docs/LOGGING_AND_PRIVACY.md`,
  THREAT_MODEL N11/N12, backlog M2-5 (the `edge-integration` flag set)

## Context

ADR-0002 Option 1 records `{session, timestamp, hostname, port, bytes, duration}` for every
connection the egress terminates. ADR-0001 variant C2 forces *all* research-browser traffic
through that egress. Both were designed independently and both work as intended. Their
combination produces a consequence neither ADR anticipated, observed for the first time on
2026-09-04 when the two ran together end to end for the first time.

A browser generates a great deal of traffic nobody asked for. Driving the research browser
through the real protected path to visit **one** site, the egress logged the requested host plus:

```
config.edge.skype.com          nav-edge.smartscreen.microsoft.com
clients2.google.com            data-edge.smartscreen.microsoft.com
edge.microsoft.com             msedgeextensions.sf.tlu.dl.delivery.mp.microsoft.com
www.bing.com                   clients2.googleusercontent.com
www.googleapis.com
```

Under C2 that is the design working: register item 4 showed this same traffic escaping to nine
third-party endpoints via ordinary corporate egress when enforcement was absent, and being
comprehensively contained when it was present. Containing it is correct. The question this ADR
raises is what happens to it **once contained**, because containment means it is now recorded.

Three consequences follow:

1. **Attribution accuracy.** The audit trail conflates browser-originated connections with
   analyst-directed navigation. Nothing in a hostname record distinguishes "the analyst chose to
   visit this" from "the new-tab page fetched this". A reviewer, a Wazuh correlation rule, or a
   future conduct enquiry reading a session log can reasonably misread `www.bing.com` as a
   deliberate visit. These are records about identified people, retained for governance purposes;
   records that attribute activity a person did not initiate are a data-accuracy problem before
   they are an engineering one.
2. **Volume and retention.** Background connections are a large and roughly constant share of
   records per session, independent of how much research is actually done. This interacts with
   D-09 retention sizing and with the signal-to-noise ratio of anything built on this data.
3. **Egress fingerprint.** The approved NAT addresses continuously contact Microsoft and Google
   service endpoints, which associates those addresses with an enterprise Edge fleet. Minor, and
   noted for completeness rather than as a driver.

Note that suppression is unaffected: during an approved sensitive session hostnames are not
recorded at all, so this concerns normal sessions only.

## Decision

**None yet — this ADR exists to put the choice in front of the owner rather than let it be
settled implicitly by whatever flag list ships with M2-5.** The recommendation below is
Option B + D.

## Alternatives considered

### Option A — Disable background services broadly in the research profile

Turn off the browser's background network activity through policy: prefetch/preconnect, search
suggestions, new-tab content, extension update checks, and SmartScreen.

- **Pros:** Directly removes the noise at source. Smallest telemetry footprint. Fewest records
  about activity nobody initiated.
- **Cons:** **SmartScreen is a protective control, not noise.** Research analysts visit hostile
  infrastructure by definition; disabling reputation checking to obtain tidier logs trades
  analyst safety for readability, which is the wrong direction. Extension update checks carry
  patch-delivery value on the same reasoning.
- **Verdict:** rejected as stated. Its non-protective subset is Option B.

### Option B — Disable only the non-protective background services (**recommended**)

Disable the categories that are convenience or vendor telemetry and carry no protective value:
network prediction (prefetch/preconnect — already wanted independently by THREAT_MODEL N12),
search suggestions, new-tab content feeds, and optional vendor diagnostics. **Retain SmartScreen
and extension updates.**

- **Pros:** Removes a substantial share of the noise without weakening a security control.
  Prefetch disablement is already required for a separate reason, so part of this is not new
  scope.
- **Cons:** Does not eliminate the problem — SmartScreen and update traffic remain, so the audit
  trail still contains records the analyst did not cause. Reduces, does not resolve.
- **Note:** the exact policy and flag names must be pinned behaviourally before shipping, by the
  method used for ADR-0001 register items 2 and 5. `NetworkPredictionOptions` is a documented
  candidate; the others are not yet verified. An unrecognised policy name sits in the registry
  looking correct and does nothing, so no name enters `edge-integration/` unverified.

### Option C — Classify background traffic at ingest

Keep the traffic but mark browser-infrastructure hostnames distinctly, so the record separates
navigation from background activity.

- **Pros:** Solves attribution properly rather than partially. Preserves the full record.
- **Cons:** There is **no reliable server-side signal** for this. Envoy sees `CONNECT host:port`
  and nothing about intent; distinguishing them genuinely requires browser-side reporting, which
  is ADR-0002 Option 2 and was rejected on privacy and tamper-resistance grounds. The fallback is
  a maintained hostname allowlist, which is brittle across browser versions and — more seriously —
  **becomes an evasion target**: anything an adversary can get classified as background is
  activity that reads as noise in the audit trail. A security-relevant allowlist that quietly
  downgrades records is a poor trade for cosmetic clarity.
- **Verdict:** not recommended for MVP. Revisit only with a trustworthy signal, not a list.

### Option D — Document the limitation explicitly (**recommended alongside B**)

State in `LOGGING_AND_PRIVACY.md`, in the analyst/approver-facing description of what is
recorded, and in the management UI's session view, that hostname telemetry includes connections
the browser makes on its own and is therefore not a record of deliberate navigation.

- **Pros:** Costs nothing, removes the misreading risk at the point where the misreading would
  happen, and is honest about a limitation that Option C cannot actually fix. Supports the
  accuracy expectation directly: the record is not claimed to be something it is not.
- **Cons:** Relies on readers reading. Does not reduce volume.

## Security/privacy consequences

- No change to what is collected under Option D; Option B **reduces** collection, so it does not
  trip the CLAUDE.md "materially increasing data collection" stop condition. It does change what
  the research browser does on the network, so it belongs in the M2-5 flag set and needs the same
  verification discipline.
- Retaining SmartScreen means the egress continues to disclose visited hostnames to Microsoft's
  reputation service. That is true of the current design and is **not** introduced by this ADR,
  but it is worth stating plainly here: for a research browser used to examine hostile
  infrastructure, hostnames leave the platform to a third party by design. If that is
  unacceptable for some categories of research, the answer is a separate decision about
  SmartScreen for those sessions, not a general disablement.
- Option C is recorded as rejected specifically so that a future "just allowlist the noisy
  hostnames" suggestion has a written reason to argue against.

## Operational consequences

- Option B is a change to the `edge-integration` flag/policy set (M2-5), deployed with it, and
  reversible by redeploying the profile. No infrastructure change.
- Option D is documentation plus a line of UI text in the management console's session view.
- Neither affects the egress, the control plane, or the audit schema.
- Whichever is chosen, the M1-5 verification method should confirm the resulting flag set still
  passes register items 2, 4 and 5 — changing background-service behaviour is exactly the kind of
  change that could move startup traffic.

## Approval

**Not yet approved.** Requires the project owner (research-browser behaviour, SmartScreen
trade-off) and DPO input (accuracy of records attributed to identified analysts). Record the
outcome as a D-number in `docs/PHASE0_DECISIONS.md` and update ADR-0002's Related list, since
this qualifies how its Option 1 telemetry should be read.
