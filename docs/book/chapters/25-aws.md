# Phases 3–5 — AWS Foundation, Deployment and Edge

<p class="lead">The three AWS phases run as one focused deployment window after the local work is finished. The Terraform is written and statically scanned before anything is applied. <span class="status plan">Planned</span></p>

## Phase 3 — Terraform AWS foundation

VPC with public, private-application and isolated-data subnets; routing; tiered security groups; IAM roles per function; ECR; and the Terraform state architecture (ADR-0014):

- **State.** An S3 backend with native lockfiles (`use_lockfile = true`, Terraform ≥ 1.10). The bucket is SSE-KMS encrypted and versioned, with public access blocked, a TLS-only policy and access logging. A small `bootstrap/` stack creates it.
- **Per-environment roots.** `backend.tf` and `providers.tf` live inside each `environments/<env>/` directory, not at the root. A shared root backend is the most common way development work lands on production state.
- **Guards.** `allowed_account_ids` on every provider, `default_tags` stamping the environment, and CI roles scoped by OIDC `sub`.
- **Checkov clean** on every module: no public databases, no open security groups, no unencrypted storage, no missing logging.

## Phase 4 — Application deployment

ECS Fargate for the API and worker, an **internal** ALB (HTTPS, desync mitigation "strictest", invalid headers dropped), and RDS PostgreSQL in isolated subnets with KMS and `rds.force_ssl`. Secrets Manager replaces `.env`, scoped per task as it is per container locally. CloudWatch logs and alarms. Two items close Phase 2 caveats:

- The RDS master is granted the membership needed to transfer schema ownership, and the **same** `bootstrap-roles.sh` runs as a one-off task.
- The audit chain head is exported to **S3 with Object Lock**, anchoring the log outside the database.

Client-IP trust switches from the local edge subnet to the ALB subnet ranges, with no code change, only configuration.

## Phase 5 — CloudFront, WAF and TLS

Route 53 (with CAA), CloudFront with ACM certificates (TLS 1.2+), the SPA from private S3 through Origin Access Control, and `/api/*` through a **VPC origin** to the internal ALB. AWS WAF gets managed rule groups, custom rules and rate-based rules scoped per path (`/api/v1/auth/*` tight, `/api/*` general). A CloudFront response-headers policy carries the SPA headers, with a test comparing it to the local nginx policy. Validation proves the origin is **unreachable from the internet**, and WAF rules are tested against the project's own domain only. Certificate monitoring with expiry alerts feeds the dashboard.

:::planned Cost discipline
An always-on development environment is roughly $110–125 per month. The plan is deploy, capture evidence (plan/apply output, WAF blocks, origin-unreachable proof, a recorded walkthrough) into `docs/evidence/`, then destroy. Re-creating it for an interview costs a few dollars.
:::
