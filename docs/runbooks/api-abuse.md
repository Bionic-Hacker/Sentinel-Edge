# Runbook: API abuse

- **Severity guidance:** SEV2 if COR-004 (authorization probing) fired for an authenticated
  account, or abuse degrades the service; SEV3 for COR-005 (repeated rate-limit trips) alone.
- **Owner role:** ANALYST (triage), SECURITY_ENGINEER (containment)
- **Related threats / controls:** T-API-01, T-API-02, T-API-04, T-SO-03 · C-API-01, C-API-02,
  C-API-03, C-SO-04
- **Last exercised:** 2026-10-07, attack simulator scenario "API abuse"

## 1. Detection

| Signal | Where |
|---|---|
| **COR-005 API abuse**: 3+ rate-limit trips from one address in 10 minutes | Threats page (MEDIUM; does not open an incident on its own) |
| **COR-004 Authorization probing**: 5+ BOLA/BFLA denials by one account in 10 minutes | Threats page (HIGH; opens an incident) |
| `ratelimit.exceeded` at the start of each throttled run | Audit logs |
| Endpoints marked *elevated* (throttled or 5+ forbidden responses) | API Security Center (`/apis`) |
| Unknown-path requests climbing | Dashboard → API traffic; API Security Center |

Distinguish abuse from a broken client: a buggy integration retries one endpoint with the same
request; abuse walks IDs (`/users/{id}`, `/applications/{id}`) or many endpoints, often from an
account that has no reason to call them.

## 2. Triage (first 15 minutes)
1. If COR-004 fired, open its incident and triage it; otherwise open one from the COR-005
   detection if the activity continues.
2. Identify the account (COR-004) or address (COR-005), the endpoints involved, and the window.
3. Check impact on the dashboard: rejected and server-error counts, mean response times.

## 3. Investigation
1. Threats page, filter *Category: BOLA attempt* or *BFLA attempt*, then the account: which object
   IDs or functions were requested. Every such denial returned 404 or 403 and was audited.
2. Audit logs, `authz.denied` for the account: the full endpoint and object of each attempt.
3. Was anything **allowed** that should not have been? Compare the account's successful requests
   with what its role permits (authorization.md). An allowed object outside the account's scope
   is a real BOLA and raises the incident to SEV1.
4. For volume abuse: which policy throttled it (the `ratelimit.exceeded` record names it).

## 4. Containment
1. Probing account: Settings → Users → **Deactivate** (sessions revoked at once).
2. Volume from one address: the per-IP limits already throttle it and fail closed. An edge block
   is a Terraform WAF change (Phase 5).
3. If a real authorization gap was found: disable the endpoint through a reviewed change.

## 5. Remediation
Fix any gap in the service-layer check and add the case to `test_authz_matrix.py` or the
object-level tests. Tune a rate-limit policy only with evidence, in `api_policy.py`, reviewed.

## 6. Validation
- The authorization tests cover the fixed case; the matrix sweep passes.
- No new COR-004 or COR-005 detections for the source.

## 7. Rollback
Reactivate the account after review; revert temporary endpoint changes once the fix ships.

## 8. Post-incident
Close with *Resolved*, or *False positive* for a misbehaving but legitimate client (and fix the
client). Record lessons learned.
