# Incident response

How SentinelEdge detects, records and works security incidents, and how the evidence stays
trustworthy. Everything here is **LOCAL**; simulated incidents follow the same process and are
labelled **SIMULATED**. The design decisions are in
[ADR-0018](adr/0018-security-event-pipeline-and-incidents.md); scenario-specific steps are in the
[runbooks](runbooks/).

## From signal to incident

```
request ──► HTTP analysis (17 detect-only rules) ─┐
sign-in, MFA, refresh-token reuse ────────────────┤
authorization denial (BOLA / BFLA) ───────────────┼─► security event (append-only)
rate-limit trip ──────────────────────────────────┤        │
audit-chain tampering ────────────────────────────┘        ▼
                                                 correlation rules COR-001…007
                                                 (same transaction, audit lock)
                                                            │
                         detection ≥ HIGH, any CRITICAL event, token theft,
                         suspicious authentication or audit tampering
                                                            ▼
                         incident (one open per provenance + source; new matches join it)
```

An incident can also be opened by hand (Incidents → New incident) or from any event on the
Threats page (**Open an incident from this event**), which links that event as evidence.

## Lifecycle

| Status | Meaning | Typical exit |
|---|---|---|
| DETECTED | Opened by the engine or a person; nobody has looked yet | Triage |
| TRIAGED | Someone owns it; scope and severity confirmed | Start investigating |
| INVESTIGATING | Gathering evidence: events, audit records, logs by correlation ID | Contain |
| CONTAINMENT | Stopping further harm: sessions revoked, accounts deactivated, blocks requested | Fix |
| REMEDIATION | Fixing the root cause through a reviewed change | Validate |
| VALIDATION | Proving the fix: tests, replayed or simulated events, no new detections | Close, or *Validation failed* back to REMEDIATION |
| CLOSED | Resolution recorded: resolved, accepted risk, false positive or duplicate | Reopen (leads) |

Any open incident can be **closed as not an incident** (false positive or duplicate) by a lead,
with a note. Statuses advance one step at a time, so every incident's timeline shows the whole
path. Who may do what is in the [incident permission matrix](authorization.md#incident-permission-matrix-phase-7).

## Severity and risk score

Severity (info, low, medium, high, critical) comes from the detection and can be raised by later
evidence: a request that was served, a successful sign-in from a stuffing source, a critical event
joining the incident. Leads can change it, with the change recorded on the timeline.

The **risk score** (0 to 100) explains priority as a sum of stated factors (severity, whether an
attack request succeeded, whether a critical-risk endpoint was targeted, and so on), each shown
with its points. It never hides how it was reached.

## Roles during an incident

| Role | Responsibility |
|---|---|
| ANALYST | Triage, investigate, record notes; works incidents they own |
| SECURITY_ENGINEER | Lead: assigns, changes severity, contains, closes and reopens |
| ADMIN | Lead; also performs account containment (deactivate, reset 2FA) |
| VIEWER | Reads incidents and evidence (for example management or audit) |

The project has one maintainer, so separation of duties is enforced by roles, not by different
people (threat model, residual risk).

## Evidence handling

- **Events are immutable.** The application's database role can insert and read security events
  but never update or delete them.
- **Evidence links are write-once.** An event can belong to one incident, set once by a trigger;
  it cannot be moved or detached.
- **The timeline is append-only.** Status changes, assignments, edits and notes are timeline
  entries. Notes cannot be edited or deleted; correct a note by adding another.
- **Tampering is detectable.** Each entry's SHA-256 digest is committed to the hash-chained audit
  log in the same transaction. Every read re-verifies them; the **Evidence integrity** panel shows
  *Verified* or names the first entry that no longer matches. `make verify-audit` checks the chain.
- **Incidents are never deleted.** Close them with a resolution instead.
- **Attacker data is shown as text.** Payload snippets, user agents and request fields are never
  rendered as markup, under a CSP that forbids inline script. Sensitive fields (passwords, tokens,
  codes) are stored as `[REDACTED]`.
- **Concurrent work is safe.** Every change names the version it was based on; if someone else
  changed the incident first, the change is refused and the page asks you to reload.

## Live and simulated

Correlation never mixes provenance, so simulated activity can only ever raise simulated
detections and incidents. The dashboard, Threats and Incidents pages show one view at a time,
and the simulated view carries an amber banner. Practising the workflow on a simulated incident
is encouraged; it can never touch a real record.

## Planned

AI-assisted analysis that separates observed evidence from inference, with human approval for
any proposed action (Phase 9); real AWS WAF logs as a live event source (Phase 5); a retention
policy and export for closed incidents (Phase 12).
