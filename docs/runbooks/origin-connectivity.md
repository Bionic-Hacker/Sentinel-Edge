# Runbook: Origin connectivity (CloudFront cannot reach the ALB)

- **Severity guidance:** SEV1: the whole API is unreachable through the edge
- **Owner role:** ADMIN
- **Related threats / controls:** T-EDGE-03, T-ORG-01; C-EDGE-02, C-LB-01
- **Last exercised:** not yet (Phase 12)

## 1. Detection
Pages load but every `/api/*` request returns 502 or 504 from CloudFront; `make edge-check` fails on "the API is ready" while the ALB's targets are healthy.

## 2. Triage (first 15 minutes)
Check in order: the ALB's targets are healthy; the ALB's security group admits `CloudFront-VPCOrigins-Service-SG`; the VPC origin is `Deployed`; the origin certificate is ISSUED and names the platform.

## 3. Investigation
A 502 with healthy targets is almost always TLS between CloudFront and the ALB (certificate, host name) or the security-group rule; a 504 is a slow origin (an AI analysis over 60 seconds).

## 4. Containment
Never work around it by making the ALB public or adding a second origin: the private origin is the control (ADR-0001).

## 5. Remediation
Re-plan the dev stack (`make tf-plan STACK=dev`): drift in the ingress rule or origin shows there. Apply the reviewed plan.

## 6. Validation
`make edge-check` passes, including "the ALB cannot be reached from the internet".

## 7. Rollback
Revert the Terraform change that caused it through a pull request and the pipeline.

## 8. Post-incident
Record what happened in the incident's timeline, and update this runbook if a step was wrong.
