# Runbook: Certificate expiration

- **Severity guidance:** SEV2 at 30 days, SEV1 at 14 days or a failed renewal
- **Owner role:** SECURITY_ENGINEER
- **Related threats / controls:** T-EDGE-10; C-EDGE-06
- **Last exercised:** not yet (Phase 12)

## 1. Detection
A `certificate` security event: expiring in 30 days (high at 14), renewal failed, or the certificate expired, revoked or failed (ADR-0029). `make report KIND=certificates` lists days left.

## 2. Triage (first 15 minutes)
Open the Certificates page: which certificate (us-east-1 edge or home-Region origin), its renewal status and eligibility.

## 3. Investigation
ACM renews DNS-validated certificates on its own when the validation record still exists in the zone and CAA allows Amazon. A failed renewal almost always means one of those changed.

## 4. Containment
Nothing to contain: an expiring certificate still works. Act before the date.

## 5. Remediation
Check the validation CNAME and the CAA records in the zone (`dig CAA <domain>`); restore them through Terraform. If renewal cannot succeed, request a new certificate in the stack and apply.

## 6. Validation
The Certificates page shows ISSUED with a new expiry; no new certificate event.

## 7. Rollback
Not applicable: certificates are replaced, not rolled back.

## 8. Post-incident
Record what happened in the incident's timeline, and update this runbook if a step was wrong.
