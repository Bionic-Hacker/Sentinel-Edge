# Introduction

<p class="lead">Most security portfolios show a tool. SentinelEdge shows a system: an internet-facing, AI-assisted application whose design, code, infrastructure, pipeline and governance are all built to be defended in an interview, line by line.</p>

## What SentinelEdge is

SentinelEdge is an application, API and edge security platform. When complete, it gives a security team one place to see and act on the security of a web application:

- edge and WAF activity, with rule changes governed through Terraform;
- an inventory of every API endpoint, its controls and its traffic;
- security events, incidents and their investigation from detection to closure;
- vulnerability findings from SAST, SCA, DAST, IaC and container scanning, and SBOMs;
- AI-assisted analysis of events through Amazon Bedrock, with prompt-injection defenses and human approval;
- threat models, a control matrix, risk exceptions with expiry, and change records.

It deliberately resembles a simplified enterprise security platform. It is not a generic SaaS application and it is not an AI chatbot. The application itself has to demonstrate security engineering competence.

## The first protected workload

The design rests on one idea: **SentinelEdge protects itself first.** The WAF it reports on sits in front of SentinelEdge. The rate limits its API Security Center displays are the limits enforced on its own API. The audit log it verifies records its own administrators' actions. The attack simulator targets only SentinelEdge, never an external system.

This removes the usual gap between a demo and reality. Every dashboard figure is backed by a control actually running on the platform. Where a control cannot run yet (AWS WAF before the AWS phases, say), the platform says so explicitly rather than simulating it silently.

## Design principles

1. **Defense in depth.** Eighteen layers, from DNS to governance, each with a stated reason to exist (Chapter 5). No single control is load-bearing.
2. **Secure by default.** No default credentials, interactive API docs off when deployed, insecure configuration refused at startup, every container non-root and read-only.
3. **Evidence over assertion.** Every claimed control has a negative test that proves the attack fails, and the documentation points to it. An OWASP mapping that cites a test fails CI if that test disappears.
4. **Real versus simulated, enforced in code.** Every capability carries a provenance label (REAL_AWS, LOCAL, SIMULATED, DEMO). Tests stop a simulation being presented as an AWS control.
5. **Decisions are written down.** Every decision with security trade-offs gets an Architecture Decision Record (ADR) covering context, decision, security impact, alternatives and consequences. Twenty-three exist so far.
6. **Build incrementally, stop for approval.** Twelve phases, each ending in a tested, documented, tagged release and a deliberate pause before the next.
7. **Spend nothing until it buys something.** All local phases are built before any AWS resource exists, so cloud infrastructure runs for one focused window instead of idling for months.

## Who it is for

The project is built to support conversations for these roles:

| Role | Where the evidence is |
|---|---|
| Application / Product Security Engineer | Authentication, RBAC, audit log, secure error handling (Chapters 6–7) |
| API Security Engineer | Rate limiting, inventory, OWASP API Top 10 coverage (Chapter 8) |
| Cloud Security Engineer | Private-origin AWS design, IAM, state isolation (Chapters 3, 13) |
| WAF / CDN Security Engineer | CloudFront, WAF rule governance via Terraform (Chapters 3, 13) |
| DevSecOps Engineer | Shift-left gates from Phase 1, scan gate, SBOMs, authenticated DAST, vulnerability management, OIDC pipeline (Chapters 6, 10, 14) |
| AI Application Security Engineer | Bedrock integration, output contract, human approval (Chapter 12) |
| Security Operations | Events, incidents, runbooks, attack simulator (Chapter 9) |
| GRC / Security Governance | Threat models as code, control catalogue, explainable posture score, exceptions and change management with separation of duties (Chapter 11) |

## Current status

| Phase | Scope | Status |
|---|---|---|
| 1 | Architecture, repository, ADRs, local environment, CI baseline | <span class="status done">Complete · v0.1.0</span> |
| 2 | Secure application foundation: auth, MFA, RBAC, audit logging | <span class="status done">Complete · v0.2.0</span> |
| 6 | API security: inventory, OWASP API mapping, rate limiting | <span class="status done">Complete · v0.3.0</span> |
| 7 | Security operations: events, dashboard, incidents, simulator | <span class="status done">Complete · v0.4.0</span> |
| 8 | Application security scanning, SBOM, vulnerability management | <span class="status done">Complete · v0.5.0</span> |
| 10 | Threat modeling and governance | <span class="status done">Complete · v0.6.0</span> |
| 9 | AI security | <span class="status next">Next</span> |
| 3, 4, 5 | AWS foundation, deployment, CloudFront + WAF + TLS | <span class="status plan">Planned</span> |
| 11, 12 | Automation pipeline · hardening and final review | <span class="status plan">Planned</span> |

Phase numbers come from the original specification and keep their meaning everywhere. The *build order* differs from the numbering on purpose; Chapter 2 explains why.
