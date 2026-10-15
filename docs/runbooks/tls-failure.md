# Runbook: TLS failure at the edge

- **Severity guidance:** SEV1 if browsers refuse the site; SEV2 for one client type
- **Owner role:** ADMIN
- **Related threats / controls:** T-EDGE-02; C-EDGE-01
- **Last exercised:** not yet (Phase 12)

## 1. Detection
Browsers show a certificate or protocol error; `make edge-check` fails at the TLS check; `openssl s_client -connect <domain>:443 -servername <domain>` fails.

## 2. Triage (first 15 minutes)
Read the certificate CloudFront serves (`openssl s_client … | openssl x509 -noout -subject -enddate`) and the Certificates page (status, days left, renewal).

## 3. Investigation
Causes: the certificate expired or failed renewal (see certificate-expiration.md), the alias points elsewhere, or a client older than TLS 1.2 (`TLSv1.2_2021` is deliberate).

## 4. Containment
Do not lower the minimum TLS version to admit an old client.

## 5. Remediation
Fix the certificate or the alias records in Terraform; apply the reviewed plan.

## 6. Validation
`make edge-check` TLS and redirect checks pass; the Certificates page shows ISSUED.

## 7. Rollback
Revert the Terraform change through a pull request.

## 8. Post-incident
Record what happened in the incident's timeline, and update this runbook if a step was wrong.
