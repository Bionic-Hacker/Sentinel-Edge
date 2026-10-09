# Architecture Blueprint

<p class="lead">This chapter describes the target architecture on AWS, the local topology that stands in for it today, and how the application itself is structured. Each integration sits where it does for a security reason, and that reason is stated alongside it.</p>

## Target architecture on AWS

{{figure:aws|Target AWS architecture. Amber: edge (Phase 5). Teal: VPC workloads (Phases 3–4). Violet: AI (Phase 9).}}

A request travels through these tiers:

1. **Route 53** resolves the domain. A CAA record allows only Amazon to issue certificates for it, so a mis-issued certificate from another CA is refused at issuance.
2. **CloudFront** terminates TLS (TLS 1.2+ with an ACM certificate) close to the user and applies a response-headers policy.
3. **AWS WAF** is attached to the distribution and evaluated *at the edge, before any origin request*. It applies managed rule groups, custom rules and rate-based rules.
4. CloudFront routes by path. `/*` goes to a **private S3 bucket** holding the SPA, reached through Origin Access Control. `/api/*` goes through a **CloudFront VPC origin** to an **internal Application Load Balancer**.
5. The ALB forwards to **ECS Fargate** tasks in private subnets with no public IP addresses.
6. The tasks reach **RDS PostgreSQL** in isolated subnets with no route to the internet, encrypted with KMS and requiring TLS.
7. The API calls **Amazon Bedrock** with its IAM task role, reads secrets from **Secrets Manager**, and logs to **CloudWatch**. CloudTrail records API activity. Audit records are archived to S3 with Object Lock.

Security groups chain the tiers. The ALB admits only the CloudFront VPC-origin service security group. The application admits only the ALB on port 8000. The database admits only the application on port 5432.

:::note A correction to the specification's diagram
The specification draws WAF as a network hop between CloudFront and the ALB. In AWS, WAF is attached to the CloudFront distribution and evaluated at the edge, before the origin request is made. The security outcome is the one the specification intends, but the documentation describes the real mechanism, because an interviewer will know the difference.
:::

## Why each integration sits where it does

### No public origin (ADR-0001)
If the load balancer were internet-reachable, an attacker who found it could bypass CloudFront and the WAF entirely (threat T-EDGE-03). The common mitigations are an ALB security group limited to the CloudFront prefix list, plus a secret header. They reduce the risk but leave a public endpoint, and the prefix list admits traffic from *any* CloudFront distribution, including an attacker's. Making the ALB **internal** and connecting it with **CloudFront VPC origins** removes the bypass path instead of mitigating it. The trade-off is that tasks need NAT or VPC endpoints for egress.

### One origin, no CORS (ADR-0002)
The SPA and the API share one hostname. CloudFront (locally, nginx) routes `/api/*` to the API and everything else to the SPA. There is therefore no CORS policy to misconfigure, and the API sends no `Access-Control-Allow-*` headers at all. The refresh cookie can be `SameSite=Strict` and host-only, and one WAF web ACL and one headers policy cover all traffic. The SPA's API client refuses absolute and protocol-relative URLs, so it cannot be tricked into calling another origin.

### WAF changes only through Terraform (ADR-0008)
A dashboard holding `wafv2:Update*` permissions would be a high-value target and would make Terraform state drift from reality. The application gets a **read-only** WAF role. A requested change becomes a change request. Once approved, it is applied by a pull request that updates Terraform variables, and CI plans and applies it. In-dashboard rule toggling exists only in the simulator and is labelled SIMULATED. Real changes take minutes, not seconds. That is how mature teams operate.

### Amazon Bedrock via IAM role (ADR-0006)
The AI engine uses Amazon Bedrock (Anthropic Claude models) behind a provider interface. The ECS task role is granted `bedrock:InvokeModel` on specific model ARNs only. No API key exists, so there is no AI secret to store or leak. Prompts can stay off the public internet through a Bedrock runtime VPC endpoint, and CloudTrail records every invocation. Locally an `offline` provider gives deterministic results for tests, and configuration validation rejects it in production.

### Security headers at two layers (ADR-0011)
Headers are set by the API middleware (strictest CSP: `default-src 'none'`) and by the edge (nginx locally, a CloudFront response-headers policy on AWS) with the SPA's policy. If the edge is misconfigured or bypassed, the application still protects itself. If the application regresses, the edge still applies headers.

### Tamper-evident audit with an off-host anchor (ADR-0005)
Audit records are hash-chained and append-only inside PostgreSQL. A chain proves that what remains is unaltered, but not that nothing was cut from the end. Periodic export of the chain head to S3 with Object Lock (Phase 4) closes that gap, so the anchor sits outside the database on purpose.

## Local topology today

Until the AWS phases, Docker Compose reproduces the same trust boundaries on one machine:

{{figure:local|Local topology. The web container stands in for CloudFront; the internal data network stands in for isolated subnets.|72}}

| Concern | Local (now) | AWS (planned) |
|---|---|---|
| Edge and routing | nginx `web` container | CloudFront (Phase 5) |
| WAF | none (labelled as such) | AWS WAF (Phase 5) |
| SPA hosting | nginx | S3 + Origin Access Control |
| API | `api` container | ECS Fargate (Phase 4) |
| Database isolation | Docker `internal: true` network, no published port | Isolated subnets + security group |
| Secrets | `.env`, generated, git-ignored, mode 600, scoped per container | Secrets Manager |
| Logs | JSON to stdout | CloudWatch Logs |
| Client IP trust | Pinned edge subnet `172.30.86.0/24` | ALB subnet ranges |

Every container is non-root, has a read-only root filesystem, drops all Linux capabilities and runs with `no-new-privileges`. Ports are bound to `127.0.0.1` only, and the database has no published port at all. Startup order is enforced: `db` initializes and runs the role bootstrap script, `migrate` applies Alembic migrations as `sentinel_migrator` and exits, `api` starts as `sentinel_app`, then `web`.

## Application structure

### Backend layering (ADR-0012)

```
backend/app/
  api/v1/        routers; authentication and authorization dependencies
  core/          config, logging, correlation IDs, middleware, errors, provenance,
                 capability register, authz, rate limiting, API policy registry
  security/      passwords (Argon2id), tokens (JWT), MFA (TOTP), rate limiter, egress guard
  services/      business rules: auth, users, audit, API inventory
  models/        SQLAlchemy ORM models
  schemas/       Pydantic request and response models
  db/            engine, sessions, migration helpers
alembic/versions/  0001 baseline … 0005 api_endpoint_stats
```

Routers call services, services call the ORM, and routers return **Pydantic response models, never ORM objects**. Request models use `extra="forbid"`. These two rules prevent excessive data exposure (a field is returned only if it is declared) and mass assignment (an undeclared field is rejected) structurally, rather than by remembering to check. Directories are created only when their first real code lands, so the tree never contains empty placeholders presented as features.

### Request pipeline

Every API request passes the same ordered set of controls:

{{figure:pipeline|The request pipeline. Middleware (teal) runs on every request; rate limits (amber) sit before and after authentication.|74}}

The order matters. Client-IP resolution runs outermost, so every later consumer (rate limiting, audit, access logs) sees the same resolved address. Per-IP limits run *before* authentication, so a flood is rejected before any password hashing. Per-account limits run *after* it, so rotating IP addresses does not reset them.

### Frontend

The SPA is React 19 with strict TypeScript, built by Vite and styled with Tailwind CSS. It calls only relative `/api/v1/...` paths through a client that refuses cross-origin URLs and redirects and validates every response's shape. The access token is held **in memory only**, never in web storage (an ESLint rule bans web storage outright). A page reload performs a silent refresh using the HttpOnly cookie, single-flight within a tab and serialized across tabs with the Web Locks API.

## Data model

Primary keys are UUIDs, so record IDs are not enumerable. Timestamps are UTC. Every telemetry table carries a non-null `provenance` column.

| Domain | Entities | Phase |
|---|---|---|
| Identity | users (MFA secret encrypted in-row), auth_sessions, refresh_tokens (hashed), mfa_recovery_codes (hashed), password_reset_tokens (hashed), outbox_messages | 2 ✓ |
| Audit | audit_log (hash-chained, append-only by grant and trigger) | 2 ✓ |
| API security | rate_limit_buckets, api_endpoint_stats (hourly, route templates only) | 6 ✓ |
| Inventory | applications | 7 ✓ |
| Telemetry and operations | security_events (append-only, write-once incident link), incidents, incident_timeline (notes are timeline entries) | 7 ✓ |
| Simulation | simulation_runs, simulated_waf_rules | 7 ✓ |
| Edge and WAF | waf_rules (mirror of AWS), waf_exceptions, ip_lists | 5 |
| Vulnerabilities and supply chain | scan_runs (insert-only), vulnerabilities, risk_acceptances (decision immutable by column grants), sboms (components and the CycloneDX document) | 8 ✓ |
| Certificates | certificates | 5 |
| AI | ai_analyses, ai_action_proposals | 9 |
| Governance and posture | controls, requirements, threat_models, model_elements, threats and their links; exceptions and change_requests (approver never the requester, decisions final); posture_snapshots (insert-only) | 10 ✓ |

## Environments

`local` and `test` run on a workstation or CI runner. `dev`, `staging` and `production` are AWS environments, each with its own Terraform root and state (ADR-0014). Configuration validation treats the AWS environments as *deployed*. In those, API docs are forced off, DEBUG logging is refused, rate limiting cannot be disabled, database TLS must be verified (`verify-ca` or `verify-full`), and the offline AI provider is rejected. Unknown environment names are refused outright.
