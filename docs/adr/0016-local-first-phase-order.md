# ADR-0016: Local-first phase order to defer AWS cost

- **Status:** Accepted
- **Date:** 2026-10-07
- **Decided by:** Bionic-Hacker (project owner)

## Context
The spec numbers twelve phases with AWS deployment at 3–5, followed by seven more phases of mostly
local work. An always-on development environment costs roughly $110–125/month (NAT gateway, ALB,
RDS, WAF, Fargate), so following the numbered order would pay for idle cloud infrastructure for
months while application features are built.

## Decision
Build everything in the original scope, in this order:

| Order | Phase | Runs on | AWS cost while building |
|---|---|---|---|
| 1 | 1 Architecture | Local | $0 |
| 2 | 2 Application foundation | Local | $0 |
| 3 | 6 API security | Local | $0 |
| 4 | 7 Security operations | Local | $0 |
| 5 | 8 Application security scanning | Local + CI | $0 |
| 6 | 10 Threat modeling and governance | Local | $0 |
| 7 | 9 AI security | Local + Amazon Bedrock API calls | Cents |
| 8–10 | 3, 4, 5 AWS foundation, deployment, edge | AWS | One focused deployment window |
| 11 | 11 Automation and full pipeline | CI + AWS | Short |
| 12 | 12 Hardening and final review | Both | Short |

- Phase numbers keep their original meaning everywhere (docs, capability register, commits).
- Terraform is written and statically scanned (`validate`, Checkov) before anything is applied,
  which costs nothing.
- While AWS resources exist, evidence is captured (plan/apply output, scanner reports, WAF blocks,
  origin-unreachable proof, a walkthrough video) into `docs/evidence/`, then the environment is
  destroyed and re-created on demand for interviews.

## Consequences
- Features that will read live AWS data (WAF logs, ACM status) are built against labelled
  SIMULATED or DEMO sources first and switched to REAL_AWS in the AWS phases. ADR-0009's
  provenance rules make that switch explicit and tested.
- Bedrock is the one AWS service used before Phase 3: on-demand calls, pennies, no infrastructure.
