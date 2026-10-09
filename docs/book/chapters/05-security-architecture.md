# Security Architecture

<p class="lead">This chapter covers the security design behind the build: eighteen defense-in-depth layers, a STRIDE threat model per trust boundary, a control matrix that links each requirement to its evidence, and the rules that keep the platform's claims honest.</p>

## Defense in depth: eighteen layers

| # | Layer | Why it exists | Phase |
|---|---|---|---|
| 1 | DNS | Records managed as code; CAA limits who can issue certificates | 5 |
| 2 | CDN / edge | Terminates TLS close to users, hides the origin, absorbs volume | 5 |
| 3 | WAF | Blocks known attack patterns before they cost origin resources | 5 |
| 4 | Load balancer | Private origin, HTTPS, desync protection | 4 |
| 5 | Security groups | Each tier reachable only from the tier above it | 3 |
| 6 | Private networking | Application and database never directly routable from the internet | 3 (local analogue: 1) |
| 7 | Authentication | Proves identity; resists credential stuffing and token theft | **2 ✓** |
| 8 | API authorization | Stops BOLA and BFLA regardless of what the UI shows | **2, 6 ✓** |
| 9 | Application validation | Rejects malformed and over-posted input; limits output | **1, 2, 6 ✓** |
| 10 | Database security | Least-privilege roles, encryption, parameterization | **2 ✓**, 4 |
| 11 | IAM | Least privilege per function, no static keys | 3, 11 |
| 12 | Secrets management | Secrets never in code, images, Terraform or CI configuration | **1 ✓** (scan), 4 |
| 13 | Logging | Traceability and forensics | **1, 2 ✓** |
| 14 | Monitoring | Detects abuse and failures | 4, 7 |
| 15 | Vulnerability management | Findings tracked to closure with SLAs | 8 |
| 16 | CI/CD security | Stops vulnerable or secret-bearing code shipping | **1 ✓**, 8, 11 |
| 17 | AI security | Contains prompt injection and AI agency | 9 |
| 18 | Governance | Risk is modelled, accepted and changed on the record, by someone other than whoever asked | 1, 10 |

The test of each layer is simple: if the layer above it fails, does this one still hold? For example, injection is stopped by WAF SQLi rules at the edge, by validated request models, and by ORM-only parameterized queries, so it is still stopped if the WAF is bypassed. Credential stuffing meets a WAF rate rule, per-IP limits, per-account lockout and then MFA.

## Threat model

The method is **STRIDE per trust boundary**. The OWASP Top 10 (2021), OWASP API Security Top 10 (2023) and OWASP Top 10 for LLM Applications (2025) serve as threat catalogues. Risk is likelihood (1–3) × impact (1–3). Each threat carries a status: *Mitigated* (control implemented and tested), *Planned (phase)*, or *Accepted (interim)* with an expiry. The model is reviewed at the end of every phase and whenever a boundary, data flow or role changes. It is at version 0.6. Since Phase 10 the same document is loaded into the application as SentinelEdge's own threat model, and other applications' models (STRIDE or PASTA) are built there (Chapter 11).

### Assets

User credentials, MFA secrets and refresh tokens; security telemetry; the audit log; WAF and edge configuration; AWS credentials and IAM roles; secrets (database credentials, JWT signing key); source, pipeline and images; AI prompts and outputs; Terraform state.

### Trust boundaries

| Boundary | Crossing | Example threats |
|---|---|---|
| TB1 | Internet → edge | Floods, TLS downgrade, cache poisoning, Host header injection |
| TB2 | Edge → origin | Origin bypass, spoofed `X-Forwarded-For`, request smuggling |
| TB3 | Browser session → API | Credential stuffing, token theft, CSRF, enumeration, BOLA, BFLA, mass assignment |
| TB4 | API → database | Exposure, credential theft, over-privileged role |
| TB5 | API → AI provider | Direct and indirect prompt injection, insecure output handling, excessive agency |
| TB6 | CI/CD → AWS | Stolen cloud keys, hijacked third-party actions |
| TB7 | Operators → platform | WAF weakened without review, audit tampering |
| TB8 | Developer → repository | Committed secrets, vulnerable dependencies |

### Top attack paths and where they break

1. **Origin bypass, then unfiltered injection.** Broken by the private origin (ADR-0001). Application-layer validation and parameterization would still hold even without the WAF.
2. **Credential stuffing, then session theft, then data access.** Broken by the WAF rate rule, per-IP limits, account lockout, MFA, 15-minute tokens checked against a live session, and RBAC with object checks. Detectable through audited failures and `ratelimit.exceeded` records.
3. **A poisoned log line leads the AI to recommend a harmful change, and an operator applies it.** Broken because AI output is schema-bound and advisory, proposals need human approval, and real WAF changes need a reviewed Terraform pull request.

### Residual risk, stated plainly

- It is a single-maintainer project. Separation of duties is enforced by role checks, not by different people. Accepted for a portfolio.
- There is no edge protection until Phase 5. The local stack is bound to 127.0.0.1 and must not be exposed.
- Deletion of the newest audit records by someone with table-owner rights is undetectable until the chain head is anchored in S3 Object Lock (Phase 4).
- A single HS256 signing key with no `kid` means rotation signs everyone out. Asymmetric keys are a Phase 12 candidate.
- A distributed attacker can still trigger the per-account lockout. It is bounded per IP and expires after 15 minutes. Edge bot controls (Phase 5) reduce it further.
- The rate limiter fails closed: if the database is down, sign-in is refused with `503`, not allowed unlimited.

## The control matrix

`docs/security-controls.md` maps each requirement to the threat it counters, the control, the implementation and the evidence a reviewer can run. Each control has an ID by family (C-ID, C-API, C-DB, C-AUD, C-WEB, C-NET, C-CICD, C-GOV, and so on). Three examples:

| Requirement | Threat | Control | Implementation | Evidence |
|---|---|---|---|---|
| Credential stuffing | T-ID-01 | WAF rate rule + app limiter + lockout + MFA | Auth service; `api_policy.LOGIN` | `test_account_locks_after_repeated_failures`, `test_login_is_limited_per_ip_with_retry_after` |
| Broken function authorization | T-API-02 | Role dependency on every route | `core/authz.py` | `test_authz_matrix.py` sweep, including a mutation check |
| Audit tampering | T-AUD-01 | Hash chain + grants + triggers + Object Lock | ADR-0005, migration 0002 | `test_audit_log.py`, `make verify-audit` |

The complete threat register and control catalogue are in Appendices B and C.

## Real, local, simulated, demo

The specification forbids presenting simulated functionality as a real AWS control. Documentation alone drifts, so this is enforced in code (ADR-0009):

| Class | Meaning | UI badge |
|---|---|---|
| **REAL_AWS** | Backed by a live, Terraform-managed AWS resource or a real AWS API response | Real AWS (green) |
| **LOCAL** | Real functionality running inside SentinelEdge | Local (blue) |
| **SIMULATED** | Safe simulation of an attack or control, against SentinelEdge only | Simulated (amber) |
| **DEMO** | Synthetic seed data for demonstrations | Demo data (violet) |

A capability register (`app/core/capabilities.py`) is served at `GET /api/v1/platform/capabilities` and rendered on every module page. Tests enforce the rules. Nothing can be marked implemented REAL_AWS before an AWS phase ships it. Simulator and demo entries can never be REAL_AWS. An implemented entry cannot come from a future phase. Wording follows suit: a real control says "Blocked by AWS WAF rule AWSManagedRulesSQLiRuleSet", and a simulated one says "Simulated block — no AWS resource was changed". After four phases there are, correctly, zero REAL_AWS capabilities, and the first SIMULATED ones (the attack simulator and its WAF) are labelled at every layer.

## Governed exceptions

When a control has to be relaxed, it is recorded in a register rather than quietly removed. Each exception names the requester, business justification, risk, compensating controls, approver, exit criteria and expiry. The configuration that implements it carries the exception ID, so the link can be audited in both directions. Two are open, both for developer tooling:

- **EXC-0001**: ESLint is held on major version 9, because the accessibility plugin does not yet support version 10.
- **EXC-0002**: TypeScript is held below version 7, because `typescript-eslint` does not yet support it.

Both expire on 2027-01-07. Phase 10 migrated them into the application, which is now the system of record (Chapter 11).
