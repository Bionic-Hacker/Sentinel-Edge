# Feature classification: real, local, simulated, demo

Spec §43 requires every feature to be classified, and forbids presenting simulated functionality
as a real AWS control. SentinelEdge enforces this in code (ADR-0009), not only here.

## The four classes

| Class | Meaning | Example | UI badge |
|---|---|---|---|
| **REAL_AWS** | Backed by a live, Terraform-managed AWS resource or a real AWS API response | WAF rule state read via `wafv2:GetWebACL` | Real AWS (green) |
| **LOCAL** | Real functionality running inside SentinelEdge | Authentication, RBAC, incident workflow, header middleware | Local (blue) |
| **SIMULATED** | Safe simulation of an attack or security control, against SentinelEdge only | Simulated SQL injection event; in-dashboard WAF toggle | Simulated (amber) |
| **DEMO** | Synthetic seed data for demonstrations | Scenario datasets for interview demo mode | Demo data (violet) |

## Rules

1. The source of truth is `backend/app/core/capabilities.py`, served at
   `GET /api/v1/platform/capabilities` and rendered on every module page.
2. A capability may become `REAL_AWS` + `implemented` only when a Terraform-managed resource and an
   integration test exist for it. `tests/unit/test_capabilities.py` fails otherwise.
3. `sim.*` and `demo.*` capabilities can never be `REAL_AWS` (tested).
4. From Phase 2, every telemetry record stores its provenance, and the UI shows it on the record.
5. Wording: real controls say what happened ("Blocked by AWS WAF rule AWSManagedRulesSQLiRuleSet").
   Simulated ones say so ("Simulated block — no AWS resource was changed").
6. When a real integration is not yet possible, the UI says "Simulation / planned API
   integration" rather than implying the action happened.

## Current register (Phase 2)

| Area | Implemented now (LOCAL) | Planned LOCAL | Planned REAL_AWS | Planned SIMULATED / DEMO |
|---|---|---|---|---|
| Platform | Health, secure errors, structured logging, Host allow-list | — | ECS, ALB, RDS (P4) | — |
| Edge / WAF / TLS | API + local edge security headers | — | CloudFront, WAF, ACM, WAF logs (P5–7) | WAF toggle simulator (P7) |
| Identity | Auth, MFA, RBAC, user admin (P2) | — | — | — |
| API security | Host allow-list, mass-assignment pattern | Inventory, rate limiting (P6) | — | — |
| Security operations | — | Incidents (P7) | WAF log ingestion (P7) | Attack simulator (P7) |
| AppSec / DevSecOps | Pre-commit + CI baseline gates | Scanning, SBOM (P8), automation tools (P11) | GitHub OIDC to AWS (P11) | — |
| AI security | — | Bedrock analysis + approval (P9) | — | — |
| Governance | Provenance register, tamper-evident audit log (P2) | Threat modelling, controls, in-app exceptions (P10) | Audit archive to S3 Object Lock (P4) | — |
| Demo | — | — | — | Demo mode, five scenarios (P12) |

After Phase 2 there are still **zero** REAL_AWS capabilities; no AWS resources exist (ADR-0016).
