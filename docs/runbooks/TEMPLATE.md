# Runbook: <title>

- **Severity guidance:** when this is SEV1 / SEV2 / SEV3
- **Owner role:** SECURITY_ENGINEER | ANALYST | ADMIN
- **Related threats / controls:** T-..., C-...
- **Last exercised:** date and scenario

## 1. Detection
Signals that trigger this runbook (alarm name, dashboard panel, log query) and how to confirm
it is real rather than a false positive.

## 2. Triage (first 15 minutes)
Scope, impact, and the decision on whether to open an incident.

## 3. Investigation
Exact queries and steps (CloudWatch Logs Insights, WAF sampled requests, audit log filters),
correlated by `correlation_id`. Evidence to preserve before changing anything.

## 4. Containment
Lowest-risk action first. Any change to AWS resources goes through a change request
(ADR-0008) unless the emergency procedure applies; emergency changes are recorded afterwards.

## 5. Remediation
Root-cause fix and the pull request that implements it.

## 6. Validation
How to prove the fix works (test, replayed simulated event, scanner result).

## 7. Rollback
How to undo containment or remediation safely.

## 8. Post-incident
Incident record closed, lessons learned, threat model and controls updated.
