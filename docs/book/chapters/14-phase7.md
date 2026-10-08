# Phase 7 — Security Operations

<p class="lead">Phases 2 and 6 already noticed hostile activity: failed sign-ins, token replay, authorization denials, rate-limit trips. Phase 7 connects those signals. It adds attack detection on every request, correlation rules that turn streams of events into detections, an incident workflow whose evidence cannot be quietly rewritten, a security dashboard, and an attack simulator that is safe by construction. Released as v0.4.0.</p>

## Milestones

| Milestone | Delivered |
|---|---|
| M0 | The engineering book's sources moved into the repository |
| M1 | Security events and detect-only HTTP attack analysis |
| M2 | Correlation rules and incident management |
| M3 | Security dashboard API, application inventory, attack simulator and simulated WAF |
| M4 | Security operations frontend: dashboard, Threats, Incidents, Applications, WAF, Automation |
| M5 | Capability register, ADR-0018 and ADR-0019, threat model v0.4, runbooks, smoke test (48 checks), v0.4.0 |

## From signal to incident

{{figure:detection|The detection pipeline. Every signal becomes an append-only event; correlation runs in the same transaction; the incident policy decides what needs a person. Simulated activity (dashed) flows through the same code but can only ever touch simulated records.|100}}

One table, `security_events`, holds every security-relevant observation, whatever produced it. Each row carries its **provenance** (LOCAL, REAL_AWS, SIMULATED or DEMO), source, category, severity, outcome, a bounded evidence document and a monotonic `seq` for paging. The application's database role may only `INSERT` and `SELECT`: it cannot change or remove an event. The single exception is the link to an incident, `incident_id`, which a trigger lets the application set exactly once. An event can be evidence for one incident and can never be moved or detached.

:::why Why one table for everything
Sign-in failures, authorization denials and injection attempts look different, but an investigation needs them side by side, ordered in time, filtered by source. One table with a category column gives every page and every correlation rule a single place to look, and one set of database grants to protect.
:::

## HTTP attack analysis (detect-only)

Seventeen rules inspect the path, query string, headers and JSON body of every API request:

| Family | Rules | Looks for |
|---|---|---|
| SQL injection | SQLI-001…006 | Tautologies, `UNION SELECT`, stacked queries, comment truncation, time-based probes, fingerprinting |
| Cross-site scripting | XSS-001…004 | Script tags, event handlers, `javascript:` URIs, embedding tags |
| Path traversal | TRAV-001…002 | Encoded and double-encoded `../`, `/etc/passwd`, `win.ini` |
| Command injection | CMDI-001 | Commands chained with `;` `|` `&&` `$( )` |
| SSRF | SSRF-001…002 | Metadata addresses, loopback URLs, `gopher://`, `file://` |
| Scanning, recon | SCAN-001, RECON-001 | Scanner user agents; `.env`, `.git`, backups, admin consoles |

Input is percent-decoded twice (attackers double-encode to slip past single decoding), and every input is size-bounded. Every pattern is linear-time; an adversarial timing test feeds each rule the input most likely to make a backtracking engine stall and fails if any rule slows down (T-SO-04, ReDoS).

The analysis **records and never blocks**. Blocking belongs to the WAF at the edge, where rules can run in count mode while they are tuned; an application that blocks on regular expressions breaks legitimate input and gives attackers a cheap way to probe its rules. A pattern in a request that was **served** (a 2xx response) is raised one severity level, because the application accepted it.

`HttpInspectionMiddleware` observes the body as the application reads it (keeping at most 32 KiB), so inspection never changes how a request is processed, and analyses it on a worker thread **after** the response has been sent. Recording is throttled per source address (30 detection events a minute), so a flood of malicious requests produces a bounded number of events; the rest are still counted by the endpoint metrics from Phase 6. Snippets from sensitive fields (passwords, tokens, codes) are stored as `[REDACTED]`.

:::lesson Analysts write about attacks
An incident note that says "SQL injection from 203.0.113.24, payload `' OR 1=1 --`" is itself a request containing SQL injection. Without care, working an incident would raise new detections. Four endpoints' free-text fields are therefore excluded from inspection, the application-layer equivalent of a WAF rule exclusion. A test checks that each exclusion names a real route and a real field, so the list cannot rot.
:::

## Correlation

A single failed sign-in is noise; ten from one address against several accounts is credential stuffing. Seven rules turn events into **detections**, which are themselves events with source `correlation`:

| Rule | Detects | Grouped by | Fires at |
|---|---|---|---|
| COR-001 | Credential stuffing | source IP | 10 failed sign-ins in 10 min against 3+ accounts |
| COR-002 | Sustained password guessing | account | 10 failed sign-ins in 15 min |
| COR-003 | Injection campaign | source IP | 5 injection events in 10 min; raised if served, lowered if all blocked at the edge |
| COR-004 | Authorization probing | account | 5 BOLA or BFLA denials in 10 min |
| COR-005 | API abuse | source IP | 3 rate-limit trips in 10 min |
| COR-006 | Automated scanning | source IP | 3 scanner or recon events in 10 min |
| COR-007 | Sign-in from a stuffing source | source IP | a successful sign-in after 3+ failures against *other* accounts in 15 min |

COR-007 is the moment credential stuffing works. It is evaluated on the successful sign-in itself, because successful sign-ins are routine and are not security events.

### Exactly once, without a worker

`record_event()` inserts the event and runs the rules **in the same transaction**, while holding the audit chain's PostgreSQL advisory lock. Audit writes already take that lock, and events derived from audited actions are recorded while it is held, so taking it first everywhere gives a single lock order: no deadlocks, and no way for two concurrent requests to raise the same detection twice. A test starts 30 threads that fail sign-ins at once and asserts exactly one detection and exactly one incident.

:::why Why not a queue and a background worker
A worker decouples detection from request latency, but it needs new infrastructure before the AWS phases, turns "exactly once" into a distributed-systems problem, and lets a detection lag behind its evidence. Correlation is a few indexed queries per *security event*, not per request, so the cost is small. The worker described in Part I is deferred until WAF log ingestion (Phase 5) and AI analysis (Phase 9) need it.
:::

Rules only count events of the triggering event's provenance. Simulated activity can raise only simulated detections; it can never push a real counter over a threshold.

## Incidents

An incident opens for a detection at HIGH or above, for any CRITICAL event, and for token theft, suspicious authentication or audit tampering on their own. There is **one open incident per provenance and source address** (falling back to the account, then the category). Later matches join it as evidence and can raise its severity, so an analyst gets one record per attacker rather than a flood of duplicates.

{{figure:workflow|The incident workflow. Status advances one step at a time. Leads close, reopen and close early; moves that end or reverse work need a note.|100}}

### The server owns the rules

| Role | May |
|---|---|
| ADMIN, SECURITY_ENGINEER (leads) | Everything below, plus close, reopen, close early, change severity, assign anyone |
| ANALYST | Work incidents they own; triage an unassigned DETECTED incident (it becomes theirs); take an unassigned one; add notes |
| VIEWER | Read |

Every incident response carries `available_moves` and `permissions`, computed from these rules for the person asking. The UI renders those and never re-derives them, so there is one implementation of the policy, and it is on the server where it can be tested (T-SO-06).

Concurrent work uses optimistic concurrency. Every change names the `version` it read; a stale change gets `409 stale_version`, and the page shows a prompt to reload rather than silently overwriting a colleague's work (T-SO-07).

### Evidence that cannot be quietly rewritten

The timeline (status changes, assignments, edits, notes) is append-only. Each entry's SHA-256 digest is written into the hash-chained audit log from Phase 2 **in the same transaction**, and every read of an incident recomputes the digests and reports `integrity.verified`, or the first entry that no longer matches. To alter an incident's history unnoticed, an attacker would have to rewrite the audit chain too, which `verify-audit` detects. Incidents are never deleted; they are closed with a resolution: resolved, accepted risk, false positive or duplicate.

:::evidence Tamper tests
Tests edit a timeline entry and delete one directly in the database, as the table owner, bypassing the application. In both cases the next read reports the mismatch and names the entry. Another test confirms the application's own role cannot update or delete incident records at all.
:::

Each incident also has a **risk score** from 0 to 100, shown as the sum of stated factors (severity, an attack request that received a success response, a critical-risk endpoint targeted). The score explains itself; it never asks to be trusted.

## The security dashboard

`GET /api/v1/security/overview?view=live|simulated&hours=1..168` returns everything the dashboard draws in one response: a status line with its reasons, incident statistics (including mean time to triage and to close), event counts by category, severity and outcome, an hourly series, top sources, rules and countries, traffic, and the state of each control family, marked *measured*, *simulated* or *planned*.

**Live and simulated are never combined.** The live view covers LOCAL and REAL_AWS records and takes its traffic from the Phase 6 endpoint metrics; the simulated view covers SIMULATED and DEMO records and takes its traffic from simulation runs. The page shows one view at a time, the simulated one under an amber banner, and while switching views it shows a loading state rather than the previous view's numbers (T-SO-02).

## Application inventory

SentinelEdge is seeded as the first protected application; others can be registered with an owner, environment, criticality and domain. The domain is recorded only: SentinelEdge never connects to it. Developers see only applications they own (others return 404 and the attempt is audited). Measures that need a later phase (WAF status, certificate, security score, last scan, vulnerabilities) say which phase connects them instead of showing a number.

## The attack simulator

The platform needs attack activity on demand to show the pipeline working, and an attack generator is exactly the kind of feature that becomes a liability. It is therefore **safe by construction** (ADR-0019):

- **No network traffic.** A scenario builds synthetic request records in memory and hands them to the same functions that analyse real requests.
- **No target.** The run endpoint takes a scenario name and nothing else: no URL, host, address or payload. There is no parameter to point it anywhere.
- **Reserved values.** Addresses come from the IETF documentation ranges (RFC 5737), names from the reserved `.example` domain; advisories are synthetic.
- **Labelled and partitioned.** Everything produced is SIMULATED, and correlation never mixes provenance.
- **Controlled.** Only leads can run scenarios; runs are rate limited and audited.

Eleven scenarios cover SQL injection, XSS, path traversal, command injection, SSRF, credential stuffing (one sign-in succeeds, so COR-007 fires), bot activity, API abuse, suspicious authentication, certificate expiry and a vulnerable dependency.

### A simulated WAF with AWS semantics

Each synthetic request passes through the real HTTP analysis rules, then a **simulated web ACL** in which every rule is set to block, count or off, then (if it was not blocked) the application's own analysis and the real correlation engine. As in AWS WAF, the first rule in block mode ends the request; a rule in count mode logs the match and lets evaluation continue.

:::evidence Defense in depth, demonstrated
With the SQL injection rules in **block** mode, a simulated campaign is stopped at the edge: every injection request is blocked, and COR-003 is raised but lowered a level because nothing got through, so no incident opens. Switched to **count** mode, the same scenario's payloads reach the application, which detects them itself; COR-003 keeps its HIGH severity and opens an incident. `make smoke` runs exactly this comparison and restores the rules afterwards.
:::

This is the only place in SentinelEdge where a WAF rule can be switched from the dashboard, and it changes simulated state only. Real AWS WAF rules still change only through reviewed Terraform pull requests (ADR-0008), and the application never receives write access to AWS WAF.

## The frontend

Six pages arrived in M4: the security dashboard, Threats (events with their HTTP analysis), Incidents (list and detail), Applications, WAF (the simulated web ACL) and Automation (the simulator). A few patterns carry the security requirements into the browser:

- **Attacker data is text.** Payload snippets, user agents and request fields are rendered as text nodes, never markup; a test feeds a `<script>` snippet through the event detail and asserts nothing executes. The strict CSP from Phase 1 (no inline script or style) backs it up (T-SO-05).
- **Every response is validated** at runtime before it is rendered, as everywhere in the client.
- **Charts without inline styles.** The column chart and bar lists are SVG with geometry in attributes, because the CSP forbids `style=`. The column chart is keyboard-operable (a slider over its columns, announcing each column's value) and has a table twin.
- **No stale answers.** Each result is tagged with the request that produced it, and "loading" is derived from that tag, so a slow response can never be shown as the answer to a newer question.

:::lesson Found by looking at a phone-width screenshot
At 390 px wide, several pages, including the existing Audit Logs and API Security pages, scrolled sideways although every table sat in its own scroll box. The cause was screen-reader-only labels: they are absolutely positioned, and inside a scroll container without a positioned ancestor their containing block is the page, so a label in a table's last column sat past the edge and widened the document. One rule, making scroll containers the containing block, fixed every page. The same review found charts whose axis text shrank with the drawing; they now measure their real width so text keeps its size.
:::

## On one machine, one incident

Locally every request comes from one address. `make smoke` deliberately replays a refresh token, locks an account and sends an injection probe, so its first run opens a "likely token theft" incident for that address, and later runs join it as evidence. That is the pipeline doing its job, documented in the upgrade notes so it does not alarm anyone, and it is a ready-made incident for practising the workflow.

:::evidence Verified in Phase 7
668 backend tests (98.6% coverage) against real PostgreSQL and 75 frontend tests. `make smoke`: 48 end-to-end checks, adding a live SQL injection probe recorded through the edge, the simulated WAF in block and count modes, both dashboard views, provenance separation and the audit chain intact afterwards. Every page checked in headless Chromium at 1440 and 390 px. Ruff, mypy (strict), Bandit, ESLint, TypeScript, the schema-drift check, Gitleaks, pip-audit and npm audit are clean.
:::
