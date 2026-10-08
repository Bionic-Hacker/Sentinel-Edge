# Runbook: SQL injection event

- **Severity guidance:** SEV1 if any injection request was **served** (2xx) and the response or
  later activity suggests data was returned; SEV2 for COR-003 at HIGH or CRITICAL (a campaign, at
  least one request reached the application); SEV3 for single events, or a campaign blocked
  entirely at the edge.
- **Owner role:** ANALYST (triage), SECURITY_ENGINEER (investigation, remediation)
- **Related threats / controls:** T-API-07, T-EDGE-03 · C-API-04, C-SO-02, C-SO-04, C-WAF-01
- **Last exercised:** 2026-10-07, attack simulator scenario "SQL injection" in block and count
  modes, and the `make smoke` live probe

## 1. Detection

| Signal | Where |
|---|---|
| HTTP analysis events SQLI-001…006 (boolean tautology, UNION, stacked queries, comment truncation, time-based probes, fingerprinting) | Threats page, *Category: SQL injection* |
| **COR-003 Injection attack campaign**: 5+ injection events from one address in 10 minutes | Threats page; opens an incident at HIGH |
| Severity raised a level because a request was served | Event outcome *Served* with a 2xx status |
| Simulated WAF events (simulations only) | WAF page; real WAF logs arrive in Phase 5 |

HTTP analysis is **detect-only**: it records the attempt and the application handles the request
normally. SentinelEdge uses the ORM with bound parameters everywhere, so a recorded payload is an
attempt, not proof of injection. The question is whether anything reached a vulnerable path.

Rule out false positives: open the event and read **What matched**. Text like `O'Brien` or
`SELECT` in a search box can match a weak pattern; tautologies, `UNION SELECT`, stacked queries and
time-based functions rarely occur by accident. Incident notes and summaries are never inspected,
so writing about an attack does not create one.

## 2. Triage (first 15 minutes)
1. Open the incident, or open one from the event (**Open an incident from this event**), and
   triage it.
2. Check every event's **Outcome** and status: *Rejected* (400, 401, 422) means validation or
   authentication stopped it before any query; *Served* (2xx) means the request completed.
3. List the endpoints targeted and whether they take the injected field into a query at all.

## 3. Investigation
1. For each served request: open the event, note the endpoint, field and correlation ID; find the
   API log lines for that correlation ID.
2. Review the code path for the field: ORM query building only, no raw SQL or string formatting
   (Bandit and Ruff `S608` guard this in CI).
3. Check the database role's statement log only if the code review is inconclusive; the app role
   cannot change schema or rewrite history (ADR-0015).
4. Look at what else the source did (Threats → *Source IP*): scanning, recon of `.env` or `.git`,
   authorization probing.

## 4. Containment
1. If a vulnerable path is confirmed: disable the endpoint (feature flag or revert) through a
   reviewed pull request; deploy.
2. At the edge (Phase 5): ensure the SQLi managed rule group is in **block** mode; a rule in count
   mode logs but lets payloads through (try it with the simulator: WAF page → *Count only*, then
   run the SQL injection scenario).
3. Record the source for an IP-set block, changed only through Terraform (ADR-0008).

## 5. Remediation
Fix the query to use bound parameters, add a regression test with the captured payload (from the
event's evidence; it is stored as text and is safe to copy), and add a validation constraint on
the field if it has a natural format.

## 6. Validation
- The regression test fails before the fix and passes after.
- Re-send the payload in a local environment: still recorded by HTTP analysis, now rejected or
  harmless.
- No new served injection events for the endpoint.

## 7. Rollback
Re-enable the endpoint by reverting the containment change once the fix is deployed.

## 8. Post-incident
Close with *Resolved* (vulnerable path fixed), *Accepted risk* (with an exception record and
expiry), or *False positive*. Update the threat model (T-API-07) if a new path was found.
