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
2. A capability may become `REAL_AWS` + `implemented` only when its phase has shipped a
   Terraform-managed resource, applied, with tests (module tests from Phase 3, integration tests
   against the deployed stack from Phase 4). `tests/unit/test_capabilities.py` pins the list.
3. `sim.*` and `demo.*` capabilities can never be `REAL_AWS` (tested).
4. From Phase 2, every telemetry record stores its provenance, and the UI shows it on the record.
5. Wording: real controls say what happened ("Blocked by AWS WAF rule AWSManagedRulesSQLiRuleSet").
   Simulated ones say so ("Simulated block — no AWS resource was changed").
6. When a real integration is not yet possible, the UI says "Simulation / planned API
   integration" rather than implying the action happened.

## Current register (Phase 3)

| Area | Implemented now (LOCAL) | Planned LOCAL | Planned REAL_AWS | Planned SIMULATED / DEMO |
|---|---|---|---|---|
| AWS foundation | — | — | **Implemented (P3):** encrypted Terraform state, account guardrails, multi-region CloudTrail, CIS alarms, budget; three-tier VPC, flow logs, security-group chain (`aws.foundation`, `aws.network`) | — |
| Platform | Health, secure errors, structured logging, Host allow-list | — | ECS, ALB, RDS (P4) | — |
| Edge / WAF / TLS | API + local edge security headers | — | CloudFront, WAF, ACM, WAF logs (P5) | — |
| Identity | Auth, MFA, RBAC, user admin (P2) | — | — | — |
| API security | Host allow-list, mass-assignment sweep, API inventory and metrics, OWASP API mapping, rate limiting, SSRF guard, trusted client IP (P6) | — | WAF rate rules (P5) | — |
| Security operations | Security events, HTTP attack analysis (detect-only), correlation rules, incident workflow, security dashboard, application inventory (P7) | Retention policy (P12) | WAF log ingestion (P5) | **Implemented (P7):** attack simulator, simulated WAF rule toggling |
| AppSec / DevSecOps | Pre-commit + CI gates; scanning (Semgrep, Bandit, Trivy, Gitleaks, Checkov), scan gate, SBOMs, authenticated DAST against the local stack; vulnerability management with SLAs and risk acceptance (P8) | Automation tools (P11) | GitHub OIDC to AWS, scans of deployed environments (P11) | — |
| AI security | Analyses of events, incidents, findings and threat models with guardrails, a verbatim-evidence output contract and lead-approved, tighten-only proposals; the deterministic `offline` analyser (P9) | — | Amazon Bedrock calls when enabled (P9; no infrastructure); task-role access from the deployed API (P4) | — |
| Governance | Provenance register, tamper-evident audit log (P2); threat modeling (STRIDE, PASTA) with SentinelEdge's model loaded from the reviewed documents, control catalogue and requirement matrix, explainable posture score with snapshots, security exceptions and change management with separation of duties (P10) | — | Audit archive to S3 Object Lock (P4) | **Implemented (P10):** a `waf_rule` change request drives the simulated WAF |
| Demo | — | — | — | Demo mode, five scenarios (P12) |

After Phase 3 there are **two** REAL_AWS capabilities, the account foundation and the network
(ADR-0025); nothing that serves traffic is deployed yet.
The AI engine is LOCAL: it runs in the local API. With `SENTINEL_AI_PROVIDER=bedrock` its model
calls go to Amazon Bedrock (the status shows REAL_AWS for them), but nothing is deployed and the
default is `disabled`; `offline` answers deterministically and says so.
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
