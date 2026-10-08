# ADR-0018: Security event pipeline, correlation, incidents and evidence integrity

- **Status:** Accepted
- **Date:** 2026-10-07
- **Phase:** 7
- **Builds on:** ADR-0005 (tamper-evident audit log), ADR-0009 (provenance), ADR-0012 (layering),
  ADR-0015 (database roles), ADR-0017 (endpoint policy registry, client IP)

## Context
Phases 2 and 6 already notice hostile activity: failed sign-ins, lockouts, refresh-token
replay, authorization denials and rate-limit trips. Each is audited, but nothing connects them.
Phase 7 must turn those signals, plus attack patterns in HTTP requests, into detections and
incidents an analyst can work from detection to closure, without letting the incident record
become something an insider (or a compromised application) could quietly rewrite.

Four constraints shaped the design:

1. **No new infrastructure before the AWS phases** (ADR-0016): no queue, no worker, no search
   cluster. PostgreSQL is the only store.
2. **Evidence must be trustworthy.** An incident is only as good as the record of what happened
   and who did what about it.
3. **Simulated activity must never touch real records** (ADR-0009). The attack simulator
   (ADR-0019) feeds the same pipeline.
4. **The UI must not invent rules.** Who may move an incident where is a security decision and
   belongs in one place, on the server.

## Decision

**One append-only event table.** `security_events` holds every security-relevant observation:
authentication failures, token theft, authorization denials (BOLA/BFLA), rate-limit trips, HTTP
attack patterns, audit tampering, and detections raised by correlation. Each row carries its
provenance, source, category, severity, outcome, a bounded evidence document and a monotonic
`seq` for paging. The application role may INSERT and SELECT only; it cannot UPDATE or DELETE
an event (database grants, ADR-0015). The one exception is `incident_id`, which a trigger lets
the application set exactly once: an event joins at most one incident and can never be moved
or detached.

**HTTP analysis is detect-only and off the request path.** `HttpInspectionMiddleware` observes
each request as the application reads it (keeping at most 32 KiB of body) and, once the response
has been sent, analyses it on a worker thread. Seventeen rules (SQLI-001…006, XSS-001…004, TRAV-001…002,
CMDI-001, SSRF-001…002, SCAN-001, RECON-001) inspect every request's path, query, headers and
JSON body. Input is percent-decoded twice and size-bounded; every pattern is linear-time, and an
adversarial timing test proves it. Snippets from sensitive fields are stored as `[REDACTED]`.
The analysis never blocks: blocking is the WAF's job at the edge (ADR-0008), and an application
that blocks on regexes breaks legitimate input. A pattern in a request that was served (2xx) is
raised one severity level, because the application accepted it. Free-text incident fields are
excluded from inspection (`INSPECTION_EXCLUSIONS`), so writing "SQL injection from …" in a note
does not raise an alert; a test checks each exclusion names a real route and field. Recording is
throttled per source address (30 detection events a minute), so a flood of malicious requests
yields a bounded number of events; the rest are still counted by API metrics. Analysis never
raises: losing a detection must not fail a request.

**Synchronous correlation under the audit lock.** `record_event()` inserts the event and runs the
correlation rules in the same transaction (the request's own transaction for events fed from
audited actions such as a failed sign-in; the analysis thread's transaction for HTTP events), while holding the audit chain's advisory lock
(`0x5E7E1ED6E`). Audit writes already take that lock, and events fed from audited actions are
recorded while it is held, so taking it first everywhere gives a single lock order (no
deadlocks). A detection therefore exists exactly when its evidence does, and is raised exactly
once per rule, key and window; a 30-thread concurrency test proves it.

| Rule | Detects | Grouped by | Threshold |
|---|---|---|---|
| COR-001 | Credential stuffing | source IP | 10 failed sign-ins in 10 min, 3+ accounts |
| COR-002 | Sustained password guessing | account | 10 failed sign-ins in 15 min |
| COR-003 | Injection campaign | source IP | 5 injection events in 10 min (raised if served, lowered if all blocked at the edge) |
| COR-004 | Authorization probing | account | 5 BOLA/BFLA denials in 10 min |
| COR-005 | API abuse | source IP | 3 rate-limit trips in 10 min |
| COR-006 | Automated scanning | source IP | 3 scanner or recon events in 10 min |
| COR-007 | Sign-in from a stuffing source | source IP | a success after 3+ failures against other accounts in 15 min |

Rules count only events of the triggering event's provenance, so simulated activity can raise
only simulated detections.

**Incident policy.** An incident opens for a detection at HIGH or above, for any CRITICAL
event, and for token theft, suspicious authentication or audit tampering on their own. There is
one open incident per provenance and source IP (falling back to account, then category): new
matches join it as evidence and can raise its severity, rather than opening a new incident per
detection. Analysts get one place to work an attack, not a flood of duplicates.

**Workflow on the server.** Statuses advance one step at a time: DETECTED → TRIAGED →
INVESTIGATING → CONTAINMENT → REMEDIATION → VALIDATION → CLOSED. Any open incident can be closed
as not an incident (false positive or duplicate) with a note; VALIDATION closes with a
resolution or fails back to REMEDIATION; a closed incident can be reopened. Leads (ADMIN,
SECURITY_ENGINEER) close, reopen, change severity and assign anyone; an ANALYST acts on incidents
they own and may triage an unassigned DETECTED one, which assigns it to them; VIEWER reads.
Every incident response carries `available_moves` and `permissions`, computed from these rules;
the UI renders them and never re-derives them.

**Evidence integrity.** The incident timeline is append-only. Each timeline entry's SHA-256
digest is written into the hash-chained audit log in the same transaction, and every read
recomputes the digests and reports `integrity.verified` (or the first mismatching entry).
Rewriting the timeline outside the application therefore requires rewriting the audit chain,
which `verify-audit` detects. Incidents are never deleted. Concurrent edits use optimistic
concurrency: every write names the `version` it read, and a stale write gets 409
`stale_version` instead of silently overwriting someone else's change.

## Security impact
Adds detection and response to T-ID-01 (credential stuffing), T-ID-03 (refresh-token replay),
T-API-01 and T-API-02 (BOLA and BFLA probing), T-API-04 (resource consumption) and T-API-07
(injection). Mitigates the new security-operations threats T-SO-01 (tampered evidence),
T-SO-02 (simulated data mixed with real), T-SO-03 (event flooding), T-SO-04 (ReDoS),
T-SO-05 (stored XSS through evidence), T-SO-06 (workflow bypass), T-SO-07 (lost updates) and
T-SO-09 (secrets in evidence). See the threat model, v0.4.

## Alternatives considered
- **Background worker or queue for correlation:** decouples request latency from detection,
  but needs new infrastructure, makes "exactly once" a distributed problem, and lets a
  detection lag its evidence. Correlation is a few indexed queries per security event (not per
  request), so the synchronous cost is small. Revisit with real traffic in Phase 12.
- **A separate lock for correlation:** two locks taken in different orders by audit writes and
  correlation would deadlock under load. One lock, always first, does not.
- **Blocking in the application on HTTP analysis:** false positives would break legitimate
  input; the WAF at the edge is the blocking layer, with count mode for tuning.
- **Mutable incident history (UPDATE in place):** simpler, but an incident could then be
  rewritten after the fact. Append-only plus digests in the audit chain makes tampering
  detectable.
- **One incident per detection:** every repeat of an attack would open a new incident;
  grouping by source keeps one record per attacker.

## Consequences
Events fed from audited actions add a few indexed queries to the request that produced them;
HTTP analysis adds none to the response, because it runs after it. Ordinary requests record
nothing. On a single machine all test traffic comes from one address, so
local smoke runs fold into a single open incident for that address (expected; see
`docs/local-development.md`). Real WAF logs (Phase 5) and certificate and dependency findings
(Phases 5 and 8) arrive as new event sources without changing the pipeline.
