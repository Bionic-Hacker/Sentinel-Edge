# DevSecOps: the pipeline and its gates

How a change gets from a commit to AWS (Phase 11, [ADR-0030](adr/0030-ci-never-touches-aws.md)).
CI holds no AWS credential; deployment is a gated command on the owner's machine.

## Stages

| Stage | Where | Fails on |
|---|---|---|
| Unit, API, security and database tests (coverage ≥ 90%) | CI `backend` | any failure |
| Lint and types (Ruff, mypy strict, ESLint, TypeScript) | CI `backend`, `frontend` | any finding |
| SAST (Semgrep with SentinelEdge's rules, Bandit) | CI `backend`, `security-scans` | the gate |
| SCA (pip-audit, npm audit, Trivy filesystem) | CI | the gate |
| Secrets (Gitleaks over every branch's history) | CI `secrets-scan`, `security-scans` | any finding |
| IaC (Checkov; Terraform fmt, validate, TFLint, module tests with a mocked provider) | CI `terraform`, `security-scans` | any failure; the gate |
| Container build and scan (Trivy), SBOMs (Syft, CycloneDX) | CI `security-scans` | the gate |
| DAST (ZAP baseline and authenticated API scan of the stack in the runner) | CI `security-scans` | the gate |
| Scan gate | CI `security-scans` | a fixable finding at the threshold, not covered by an unexpired accepted risk |
| Preflight | `make deploy-check` | not main, not clean, not `origin/main`, or any CI check not green |
| Images to ECR, Terraform plan | `make deploy` | preflight; the plan is saved for a person to read |
| Deploy, migrations, SPA | `make deploy-finish` | preflight; applies only the saved plan |
| Post-deployment validation | `make deploy-finish`, `make deploy-verify` | `edge-check` (21 checks) or the audit anchor |

A live-edge ZAP scan is part of the Phase 12 window.

## Thresholds

The gate blocks fixable critical and high findings by default. `SCAN_BLOCK_AT=medium make scan` is
stricter; `SCAN_BLOCK_AT=critical` is looser and the gate says so on every run. Vulnerabilities with
no published fix are reported on every run and block once a fix exists; accepted risks expire
(ADR-0020, ADR-0023).

## Reports

Read-only reports of the same figures the dashboard shows, as text or JSON:

```bash
make report KIND=security          # status, incidents, events, top rules and sources (24 h)
make report KIND=waf HOURS=168     # WAF blocks by rule, category and source; real and simulated apart
make report KIND=vulnerabilities   # active findings by severity, and any past their SLA
make report KIND=api-inventory     # endpoints by risk, and the public ones
make report KIND=posture           # the posture score by category
make report KIND=certificates      # ACM certificates and days left (in AWS only)
make report KIND=security FORMAT=json
```
