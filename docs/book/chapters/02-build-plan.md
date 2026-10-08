# The Build Plan

<p class="lead">SentinelEdge is built from a 60-section specification, in twelve phases. Each phase ends in a tested release and a deliberate stop for approval. This chapter explains the phases, the order they are built in, and the delivery workflow that keeps every step recoverable.</p>

## The twelve phases

The specification divides the work into twelve phases, each with a fixed scope:

| Phase | Name | Scope |
|---|---|---|
| 1 | Architecture & Repository | Repository, directory structure, architecture docs, ADRs, Docker environment, README |
| 2 | Secure Application Foundation | FastAPI, React, PostgreSQL, authentication, RBAC, API foundation, secure and audit logging |
| 3 | Terraform AWS Foundation | VPC, subnets, routing, security groups, IAM, ECR, Terraform state architecture |
| 4 | AWS Application Deployment | ECS Fargate, ALB, RDS, Secrets Manager, CloudWatch |
| 5 | CloudFront + WAF + TLS | Route 53, CloudFront, ACM, AWS WAF, HTTPS, edge security headers |
| 6 | API Security | API inventory, API security controls, rate limiting, authorization, OWASP API mappings |
| 7 | Security Operations | Event collection, security dashboard, incident management, WAF event visualization, HTTP analysis |
| 8 | Application Security | SAST, SCA, DAST, secrets, IaC and container scanning, SBOM |
| 9 | AI Security | AI security engine, prompt defense, analysis, AI risk scoring, AI audit logging, human approval |
| 10 | Threat Modeling & Governance | STRIDE, PASTA, controls, exceptions, risk acceptance, change management |
| 11 | Automation & DevSecOps | GitHub Actions, Terraform validation, security gates, automated reports, automation scripts |
| 12 | Portfolio Hardening | Full security review, dependency/IAM/Terraform/WAF/API/AI reviews, demo scenarios, final documents |

Within every phase the same twelve-step discipline applies: explain the architecture, explain the security decisions, create the files, implement working functionality, implement automated tests, implement security controls, run validation, fix errors, update documentation, explain what was completed, identify the next phase, and **stop**.

## Build order: local first

Followed in numeric order, the plan would stand up AWS infrastructure at Phases 3–5 and then build seven more phases of mostly local features on top of it. An always-on development environment (NAT gateway, ALB, RDS, WAF, Fargate) costs roughly **$110–125 per month**, so months of feature work would pay for idle infrastructure.

ADR-0016 reorders the build without changing its scope:

{{flow:order|Build order, left to right and top to bottom. Teal: complete. Amber: next. Violet: the AWS deployment window.}}

| Order | Phase | Runs on | AWS cost while building |
|---|---|---|---|
| 1–3 | 1, 2, 6 | Local | $0 (done) |
| 4–6 | 7, 8, 10 | Local (+ CI) | $0 |
| 7 | 9 AI security | Local + Amazon Bedrock API calls | Cents |
| 8–10 | 3, 4, 5 | AWS, one focused deployment window | Days, not months |
| 11–12 | 11, 12 | CI + AWS | Short |

Three rules keep this honest:

- **Phase numbers keep their original meaning** in documentation, the capability register and commits, so the specification's acceptance criteria map cleanly.
- **Terraform is written and statically scanned before anything is applied.** `terraform validate` and Checkov cost nothing.
- **Features that will read live AWS data are built first against labelled SIMULATED or DEMO sources.** They switch to REAL_AWS in the AWS phases, and the provenance rules (ADR-0009) make that switch explicit and tested.

After the AWS phases, evidence (plan/apply output, scanner reports, WAF blocks, origin-unreachable proof, a walkthrough video) is captured into `docs/evidence/`. The environment is then destroyed and re-created on demand for interviews.

## Definition of done

A phase is complete only when every item that applies to it is true. This list lives in `docs/secure-sdlc.md`:

1. The threat model is updated for any new boundary, data flow, asset or role.
2. Controls are recorded in the control matrix with implementation and evidence.
3. The capability register is updated with correct provenance, and its guard tests are adjusted deliberately.
4. Negative tests exist for every new control (the attack fails), not only positive tests.
5. All gates pass: Gitleaks, Ruff, Bandit, mypy strict, pip-audit, npm audit, ESLint, tests, coverage ≥ 90%.
6. No secrets are in code, images, Terraform or workflow files.
7. An ADR is written for any decision with security trade-offs.
8. Documentation for the phase is written, and the README status table is updated.
9. Real-versus-simulated wording is checked in the UI and docs.
10. A runbook is added or updated for any new operational failure mode.

## Delivery workflow

Every phase moves through the same pipeline, so that any point in the project's history can be recovered:

{{flow:release|Phase delivery workflow, from approval to a published GitHub release.}}

- **Branch per phase.** Work lands on `phase/N-name` (for example `phase/6-api-security`), never directly on `main`.
- **Milestones.** Each phase is cut into milestones (M0, M1, …). Each is a single commit that leaves the system working and tested. M0 is always housekeeping. The last milestone is documentation, the smoke test and release notes.
- **Verifiable delivery.** Milestones are delivered as a git bundle inside a zip, with a published SHA-256 checksum. The bundle is verified (`git bundle verify`) and fetched into the local repository, so history arrives exactly as built.
- **Local verification before push.** `make check` (every CI gate), `make smoke` (end-to-end) and `make verify-hardening` (container and network controls) must pass on the owner's machine.
- **Push, PR, CI.** The branch is pushed with a short-lived fine-grained GitHub token, pasted at push time and never stored. A pull request runs the same gates in GitHub Actions.
- **Merge, sign, release.** After a green merge, the release is tagged with an SSH-signed annotated tag (`vX.Y.0`) and published as a GitHub release with notes from `docs/releases/`.
- **Walkthrough.** Every phase ships with a step-by-step walkthrough document. It explains each step, why it comes where it does in the workflow, and the commands that produced the intended result.

:::why Why bundles instead of patches
A git bundle carries commits with their IDs, authorship and parents intact. Verifying it confirms that the prerequisite commit is present before anything is applied. The zip and checksum guard the transfer. The result is that the repository on GitHub is byte-for-byte the history that was built and tested.
:::

## Releases so far

| Release | Phase | Milestones | Headline |
|---|---|---|---|
| v0.1.0 | 1 | single commit | Architecture, secure foundation, local environment, CI baseline |
| v0.2.0 | 2 | M0–M7 | Authentication with MFA, RBAC, tamper-evident audit log, least-privilege database |
| v0.3.0 | 6 | M0–M5 | Rate limiting, trusted client IPs, API Security Center, OWASP API Top 10 coverage |
| v0.4.0 | 7 | M0–M5 | Detect-only HTTP analysis, correlation, incidents with tamper-evident evidence, security dashboard, attack simulator and simulated WAF |
| v0.5.0 | 8 | M0–M4 | One scan pipeline and fail-closed gate, authenticated DAST, SBOMs, vulnerability management with SLAs and risk acceptance |
