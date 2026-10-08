# SentinelEdge architecture

Status: Phase 2 complete. This document describes the target architecture and marks clearly which parts
exist today. Anything not marked **Implemented (local)** is a design, not a running system.

## 1. Purpose and scope

SentinelEdge is an AI-assisted application, API, and edge security platform built as a
security-engineering portfolio project. The application is its own first protected workload:
every control it reports on also protects it.

## 2. Traffic path

```
Internet
  │  DNS: Route 53 (CAA restricts issuance to Amazon)                          [Phase 5]
  ▼
CloudFront edge  ─── AWS WAF web ACL evaluated here, before any origin request [Phase 5]
  │  TLS 1.2+ (ACM cert, us-east-1), response-headers policy
  ├── /*      → S3 bucket (private, Origin Access Control)                     [Phase 5]
  └── /api/*  → CloudFront VPC origin → internal ALB (HTTPS, private subnets)  [Phase 4–5]
                  │  SG: only the CloudFront VPC-origin security group
                  ▼
               ECS Fargate tasks: api, worker (private app subnets, no public IP)
                  │  SG: only the ALB SG on 8000
                  ▼
               RDS PostgreSQL (isolated data subnets, no internet route, KMS, TLS required)
                  SG: only the app SG on 5432

Egress from tasks: NAT gateway (one in dev) for Bedrock and AWS APIs; VPC endpoints evaluated in Phase 4.
Supporting: Secrets Manager, KMS, ECR, CloudWatch, CloudTrail, S3 (logs, audit archive, SBOMs).
```

**On the spec's diagram:** spec §7 draws WAF as a hop between CloudFront and the ALB. AWS WAF is
in fact attached to the distribution and evaluated at the edge before the origin request. The
security outcome is the one the spec intends; the documentation describes the real mechanism.

## 3. Local topology (Implemented, local)

```
browser ──► web (nginx :8080, 127.0.0.1 only) ──/api/*──► api (FastAPI :8000) ──► db (Postgres)
            edge stand-in: SPA + headers                   non-root, read-only   internal-only network
```

| Concern | Local (Phase 1) | AWS (planned) |
|---|---|---|
| Edge / routing | nginx `web` container | CloudFront (Phase 5) |
| WAF | none | AWS WAF (Phase 5) |
| SPA hosting | nginx | S3 + OAC (Phase 5) |
| API | `api` container | ECS Fargate (Phase 4) |
| Database isolation | Docker `internal: true` network, no published port | Isolated subnets + SG (Phase 3–4) |
| Secrets | `.env` (git-ignored, generated, mode 600) | Secrets Manager (Phase 4) |
| Logs | JSON to stdout | CloudWatch Logs (Phase 4) |
| Headers | API middleware + nginx | API middleware + CloudFront policy |

## 4. Components

| Component | Technology | Status |
|---|---|---|
| SPA | React 19, TypeScript (strict), Vite, Tailwind CSS | Implemented (local): sign-in with MFA, setup flow, password reset, user admin, audit log viewer, API Security Center, security dashboard, Threats, Incidents, Applications, simulated WAF, attack simulator |
| API | FastAPI, Pydantic v2 | Implemented (local): health/readiness, authentication, MFA, RBAC, user admin, audit log, rate limiting, API inventory, security events, HTTP attack analysis, correlation, incidents, dashboard overview, applications, attack simulator (45 endpoints) |
| Worker | same image, separate entrypoint | Not needed yet: correlation runs synchronously in the request (ADR-0018). Revisited with WAF log ingestion (Phase 5) and AI analysis (Phase 9) |
| Database | PostgreSQL 17, SQLAlchemy 2, Alembic | Implemented (local): `sentinel` schema, migrator/app roles (ADR-0015), migrations 0001–0008 |
| Operator CLI | `python -m app.cli` in the API container | Implemented: `create-admin`, `outbox`, `verify-audit` |
| AI engine | Amazon Bedrock (ADR-0006) | Selected and validated in config; integration in Phase 9 |

## 5. Backend structure (ADR-0012)

```
app/
  api/v1/        routers — authn/authz dependencies live here (Phase 2)
  core/          config, logging, correlation IDs, middleware, errors, provenance, capabilities
  services/      business rules                               (Phase 2+)
  repositories/  data access, parameterised queries only      (Phase 2+)
  models/        SQLAlchemy ORM                               (Phase 2+)
  schemas/       Pydantic request/response models             (Phase 2+)
  ai/            provider interface, guardrails, output schemas (Phase 9)
  integrations/aws/  read-only AWS clients                    (Phase 5+)
  security/      passwords, tokens, MFA, rate limiter, egress guard, HTTP attack analysis (Phase 2, 6, 7)
```

The attack simulator lives in `services/simulator.py` (Phase 7): it is a service over the same
detection code as real traffic, not a separate generator package. Data access stays in the
services with SQLAlchemy (parameterised only); a separate repositories layer was not needed.

Directories are created when their first real code lands, so the tree never contains empty
placeholders presented as features.

## 6. Cross-cutting security mechanisms in place now

1. **Security middleware** (pure ASGI, outermost): correlation ID, security headers on every
   response including 400/404/405/500, server banner removed, structured access log (path only,
   no query strings).
2. **Correlation IDs:** accepted from upstream only if they match `^[A-Za-z0-9-_.]{8,64}$`,
   otherwise regenerated, so they can't be used for log injection or header splitting.
3. **Error envelope:** `{"error": {"code", "message", "correlation_id", "details?"}}`. Validation
   errors report field location and error type, never the submitted value.
4. **Host allow-list:** `TrustedHostMiddleware`; wildcards rejected by config validation.
5. **Secure-by-default config:** API docs off unless explicitly enabled and environment is
   local/test; DEBUG logging refused in deployed environments; unknown environments rejected.
6. **Log redaction:** keys matching password/secret/token/authorization/cookie/api key/session/
   private key are replaced with `[REDACTED]`, recursively.
7. **Provenance register** (ADR-0009).

## 7. Data model (target)

Every telemetry table carries `provenance` (ADR-0009). Primary keys are UUIDs, so record IDs are
not enumerable. Timestamps are UTC.

| Domain | Entities | Phase |
|---|---|---|
| Identity | users (MFA secret encrypted in-row), auth_sessions, refresh_tokens (hashed), mfa_recovery_codes (hashed), password_reset_tokens (hashed), outbox_messages | **2 ✓** |
| Audit | audit_log (hash-chained, append-only by grant and trigger) | **2 ✓** |
| Inventory | applications **7 ✓**; API endpoints come from the route table and the policy registry, with hourly api_endpoint_stats **6 ✓** | 6, 7 |
| Rate limiting | rate_limit_buckets | **6 ✓** |
| Edge / WAF | simulated_waf_rules, simulation_runs **7 ✓**; waf_rules (mirror of AWS), waf_exceptions, ip_lists | 5, 7 |
| Telemetry | security_events (append-only; `incident_id` write-once) | **7 ✓** |
| Operations | incidents, incident_timeline (append-only; notes are timeline entries; digests in the audit chain) | **7 ✓** |
| Vulnerabilities | vulnerabilities, scan_runs | 8 |
| Supply chain | sbom_documents, sbom_components | 8 |
| Certificates | certificates | 5 |
| AI | ai_analyses, ai_action_proposals | 9 |
| Governance | threat_models, threats, controls, control_mappings, risk_exceptions, change_requests | 10 |
| Posture | posture_snapshots (each score linked to its evidence) | 10 |

## 7a. Authentication flow (Phase 2, ADR-0003)

```
POST /auth/login ──► password ok? ──no──► 401 (uniform) + failure count → lockout at 5
        │ yes
        ├── MFA enrolled ──► 200 {mfa_required, challenge (5 min)} ──► POST /auth/mfa/verify
        │                                                                  │ TOTP or recovery code
        └───────────────────────────────────────────────────────────────► session created
                                                                             │
     access JWT (15 min, memory) + __Host- refresh cookie (rotating, HttpOnly, Strict)
                                                                             │
 every request: JWT valid → session not revoked/expired → user active → role from DB → pending setup?
```

Setup gate: `must_change_password`, or ADMIN/SECURITY_ENGINEER without MFA, restricts the session to
`/auth/me`, `/auth/logout`, `/auth/password/change` and `/auth/mfa/enroll*` until done.

## 8. Roles (RBAC, Phase 2)

Full endpoint matrix: [authorization.md](authorization.md).

| Role | Scope |
|---|---|
| ADMIN | Platform administration, user and role management, approvals |
| SECURITY_ENGINEER | Security configuration, investigations, approves AI proposals and change requests |
| DEVELOPER | Application, API, and vulnerability information for owned applications |
| ANALYST | Incident investigation and notes |
| VIEWER | Read-only |

Authorization is enforced server-side by route dependencies and service-level object checks; the
UI hides what a role cannot do, but never relies on that.

## 9. Environments

`local` and `test` run on a workstation or CI runner. `dev`, `staging`, and `production` are AWS
environments with separate Terraform roots and state (ADR-0014). Configuration validation treats
`dev`, `staging`, and `production` as deployed: API docs forced off, DEBUG refused.

## 10. Cost posture

Phases 1–2 create **no AWS resources** and cost nothing. Following ADR-0016, the remaining local
phases (6, 7, 8, 10, 9) are built before any AWS phase, so cloud resources exist for one focused
deployment window. Cost estimates and the deploy–demo–destroy workflow come with Phases 3–4. Expected always-on dev cost is
roughly $110–125/month; a demo session is a few dollars.

## 11. Decisions

See `docs/adr/`. Key ones: ADR-0001 (private origin), ADR-0006 (Bedrock), ADR-0008 (WAF via
Terraform), ADR-0009 (provenance).
