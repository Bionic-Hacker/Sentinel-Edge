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

## Current register (Phase 10)

| Area | Implemented now (LOCAL) | Planned LOCAL | Planned REAL_AWS | Planned SIMULATED / DEMO |
|---|---|---|---|---|
| Platform | Health, secure errors, structured logging, Host allow-list | — | ECS, ALB, RDS (P4) | — |
| Edge / WAF / TLS | API + local edge security headers | — | CloudFront, WAF, ACM, WAF logs (P5) | — |
| Identity | Auth, MFA, RBAC, user admin (P2) | — | — | — |
| API security | Host allow-list, mass-assignment sweep, API inventory and metrics, OWASP API mapping, rate limiting, SSRF guard, trusted client IP (P6) | — | WAF rate rules (P5) | — |
| Security operations | Security events, HTTP attack analysis (detect-only), correlation rules, incident workflow, security dashboard, application inventory (P7) | Retention policy (P12) | WAF log ingestion (P5) | **Implemented (P7):** attack simulator, simulated WAF rule toggling |
| AppSec / DevSecOps | Pre-commit + CI gates; scanning (Semgrep, Bandit, Trivy, Gitleaks, Checkov), scan gate, SBOMs, authenticated DAST against the local stack; vulnerability management with SLAs and risk acceptance (P8) | Automation tools (P11) | GitHub OIDC to AWS, scans of deployed environments (P11) | — |
| AI security | — | Bedrock analysis + approval (P9) | — | — |
| Governance | Provenance register, tamper-evident audit log (P2); threat modeling (STRIDE, PASTA) with SentinelEdge's model loaded from the reviewed documents, control catalogue and requirement matrix, explainable posture score with snapshots, security exceptions and change management with separation of duties (P10) | — | Audit archive to S3 Object Lock (P4) | **Implemented (P10):** a `waf_rule` change request drives the simulated WAF |
| Demo | — | — | — | Demo mode, five scenarios (P12) |

After Phase 10 there are still **zero** REAL_AWS capabilities; no AWS resources exist (ADR-0016).
Governance records are LOCAL. A change request of type `waf_rule` changes only the simulated
WAF, and says so; real WAF rules change through reviewed Terraform from Phase 5 (ADR-0008). The
posture score counts planned controls as not built: its AWS and AI categories score 0 until those
phases.
Vulnerability findings are LOCAL: they come from real scanner output against this repository, its
images and the running local stack. The attack simulator's "vulnerable dependency" scenario stays
SIMULATED and appears only in the simulated view.
The attack simulator and the simulated WAF are the first implemented SIMULATED capabilities: their
output is labelled at every layer (record, API view, page banner) and never mixed with live data
(ADR-0019).
