# Runbook: WAF false positive (a legitimate request blocked)

- **Severity guidance:** SEV3 normally; SEV2 if a whole feature is blocked
- **Owner role:** SECURITY_ENGINEER
- **Related threats / controls:** T-WAF-01; C-WAF-01, C-WAF-04
- **Last exercised:** not yet (Phase 12)

## 1. Detection
A user gets a 403 from CloudFront for an ordinary action; the WAF page or `make report KIND=waf` shows the blocking rule for their requests.

## 2. Triage (first 15 minutes)
Find the rule and the request in the WAF log (redacted) and decide whether the request was really legitimate. Read the matching runbook if it was an attack after all.

## 3. Investigation
Prefer the narrowest exception: a scope-down statement on that rule for one path, never disabling a managed group.

## 4. Containment
Do not change WAF from the console or the application (ADR-0008): every change is Terraform, reviewed.

## 5. Remediation
Raise a change request in the app (Governance) describing the exception, then the Terraform change in a pull request; deploy through the pipeline.

## 6. Validation
The request succeeds; `make edge-check` still blocks its SQL injection and Log4j probes.

## 7. Rollback
Revert the exception's pull request.

## 8. Post-incident
Record what happened in the incident's timeline, and update this runbook if a step was wrong.
