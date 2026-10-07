# Phase 7 — Security Operations

<p class="lead">Phase 7 turns the controls built so far into something an analyst can watch and act on: security events, a dashboard, incidents worked from detection to closure, and a safe attack simulator. <span class="status next">Next</span></p>

## Scope

- **Event collection.** A shared `security_events` store with a provenance label on every record. The first sources already exist: sign-in failures, lockouts, refresh-token reuse, authorization denials, rate-limit trips and unknown-path probes from Phases 2 and 6. WAF log ingestion arrives as a REAL_AWS source in the AWS window.
- **Security dashboard.** Overall posture, active threats, blocked and suspicious requests, open incidents and API risk. Traffic by method, response code, endpoint and source. Threats by class: SQL injection, XSS, SSRF, path traversal, command injection, credential stuffing, bot activity, API abuse and rate-limit violations.
- **Incident management.** The workflow DETECTED → TRIAGED → INVESTIGATING → CONTAINMENT → REMEDIATION → VALIDATION → CLOSED. Each incident has an owner, a timeline, related events, evidence, analyst notes and remediation, and every transition is audited.
- **Attack simulator.** Controlled, clearly labelled SIMULATED events (SQL injection, XSS, path traversal, SSRF, credential stuffing, bot activity, API abuse, suspicious authentication, expired certificate, vulnerable dependency). They target only SentinelEdge, never an external system.
- **Application inventory.** Protected applications with owner, environment, criticality, domain, API count, WAF and certificate status, security score, last scan and vulnerability count.
- **Background worker.** The same image as the API with a separate entrypoint, for ingestion and scheduled jobs.

## Design commitments already made

:::planned Carried in from earlier phases
- The incident record must preserve evidence integrity. Transitions are written to the hash-chained audit log (ADR-0005).
- Simulated events can never be labelled REAL_AWS (ADR-0009). The UI says "Simulated", and the capability register's tests enforce it.
- In-dashboard WAF rule toggles exist only inside the simulator. Real changes go through Terraform pull requests (ADR-0008).
- Analyst-entered text is rendered as text, never as HTML, consistent with the Phase 1 lint bans.
:::

## Security focus

Detection logic gets its own tests (each rule fires on its attack and stays quiet on benign traffic). Incident state transitions are enforced server-side by role. ANALYST can investigate and add notes, and closure requires SECURITY_ENGINEER or ADMIN. The simulator is labelled at every layer: API, database and UI.
