# ADR-0026: The AWS workload as built: one switch, secrets outside state, least privilege per task

- **Status:** Accepted (built and tested without AWS; applied in the Phase 4–5 deploy window)
- **Date:** 2026-10-12
- **Phase:** 4
- **Decided by:** Bionic-Hacker (project owner)
- **Builds on:** ADR-0001 (private origin), ADR-0005 (audit log), ADR-0006 and ADR-0024 (Bedrock),
  ADR-0014 (Terraform state), ADR-0015 (database roles), ADR-0016 (local-first order),
  ADR-0025 (account, domain, deploy window)

## Context
Phase 4 moves the application from Docker Compose into the dev environment Phase 3 built:
PostgreSQL on RDS, the API on ECS behind an internal load balancer, secrets in Secrets Manager,
CloudWatch for alarms. Four constraints shaped it:

- **Cost.** There is no always-free tier for ECS, RDS or load balancers on an account created after
  mid-2025. On the Free plan the sign-up credits pay, and the account cannot be billed. The owner
  chose to build Phases 4 and 5 first, at no cost, then apply both in one short window (one to
  three days, about $2.50 to $7), on Fargate Spot, with a fresh database each window.
- **Secrets.** The application needs two database passwords, a JWT signing key and an MFA
  encryption key. Terraform's usual ways of creating them (`random_password`, `secret_string`)
  write the values into the state file.
- **RDS is not a superuser.** The master user cannot change SUPERUSER, REPLICATION or BYPASSRLS on
  any role, nor hand a schema to a role it cannot `SET ROLE` to. `db/bootstrap-roles.sh` had only
  ever run as a superuser.
- **No keyless CI route** into this account (ADR-0010 addendum): images are built and pushed from
  the owner's machine.

## Decision

**One switch.** `workload = true` in `environments/dev` creates the database, the secrets, the
internal ALB, ECS and the workload's alarms; `false` removes all of them. It refuses to switch on
without NAT (`nat_mode` instance or gateway), an issued certificate (`dns_delegated`), and both
images by digest. `api_desired_count = 0` on a window's first apply lets roles and migrations run
before the API starts. What stays between windows costs cents: two ECR repositories, the audit
anchor bucket, the zone and the certificates.

**Secrets never in plan, state or logs.**
- RDS creates and holds the master password itself (`manage_master_user_password`), in Secrets
  Manager under the platform key.
- The four application secrets are generated during apply by Secrets Manager's own generator, as
  ephemeral values, and written through write-only arguments (`secret_string_wo`, Terraform 1.11).
  Terraform cannot read them back. Rotation is a new `generation`.
- The secrets themselves (`modules/app-secrets`) and their values (`modules/app-secret-values`) are
  separate modules, because `terraform test` cannot yet mock ephemeral resources: the half worth
  testing stays testable.

**Database.** PostgreSQL 17, `db.t4g.micro`, single-AZ, gp3, in the isolated data subnets;
encrypted under the platform key; `rds.force_ssl` and TLS 1.2 minimum; the application verifies the
server's certificate and host name (`verify-full`) against Amazon's CA bundle, committed in
`backend/certs` and checked by `make rds-ca`. Connections, disconnections and slow statements are
logged to an encrypted log group kept a year. One day of automated backups, no final snapshot (the
data is synthetic).

**Roles on RDS.** `db/bootstrap-roles.sh` runs unchanged in spirit everywhere. As a superuser it
clears SUPERUSER, REPLICATION and BYPASSRLS explicitly; as RDS's master it checks instead that
neither application role has them. The master is granted `sentinel_migrator` with SET but not
INHERIT, so it can hand over the schema without gaining the role's privileges, and the schema's
grants are made as its owner. Tested against a CREATEROLE-only role on PostgreSQL 16, followed by
every migration and `alembic check`.

**Load balancer.** Internal, in the app subnets, HTTPS only (TLS 1.3, and TLS 1.2 with forward-secret
AEAD ciphers), the origin certificate. Only the platform's host name is forwarded; anything else
gets a 404 from the ALB. Invalid headers dropped, desync mitigation strictest, 90-second idle
timeout (an AI analysis can take 75). Access logs in a private, TLS-only bucket with SSE-S3, the
only encryption ALB logs support. TLS ends at the ALB; the hop to the tasks stays in the private
subnets, admitted only from the ALB's security group.

**ECS on Fargate.** Four task families, one execution role each, reading only that family's
secrets:

| Task | Runs | Reads | Task role |
|---|---|---|---|
| `api` | The service, on Spot | App password, JWT key, MFA key | Bedrock: one model through its US profile |
| `migrate` | Once per release (`make ecs-task`) | Migrator password | None |
| `dbadmin` | Once per window | RDS master secret, both role passwords | None |
| `anchor` | Hourly (EventBridge Scheduler) | App password | Put and read objects under `anchors/` |

Every container has a read-only root filesystem, a non-root user, no Linux capabilities and no
shell (ECS Exec off). Images are referenced only by digest: `make images-push` builds from a clean,
committed tree, tags with the commit and pins the digests. Every app task runs as a deployed
environment, so the app itself refuses unverified database TLS, plain-HTTP origins and debug
logging.

**Audit anchors (completes ADR-0005).** Every hour the anchor task verifies the audit chain and
writes its head (sequence number and hash) to an S3 bucket with Object Lock in governance mode
(30 days), under the platform key. Its role cannot delete anchors, change their retention or bypass
the lock. `audit-anchor check` fails if the anchored record is missing or changed, which catches
the deletion of the newest records that a hash chain alone cannot see. A broken chain is never
anchored.

**Alarms** to the confirmed security-alerts topic: no healthy API task, server errors, a burst of
refused requests, requests the ALB answered itself, database CPU and storage, and errors in the
API's log.

## Security impact
- Mitigates (once applied in the window) T-DB-01 (the database), T-DB-02, T-DB-04, T-ORG-01,
  T-ORG-03, T-AUD-01's remaining tail deletion, and T-SEC-02 (secrets in Terraform state, new).
- Controls C-LB-01, C-DB-02, C-DB-04, C-AUD-03, C-MON-01 and C-SEC-04 (new) are built; C-EDGE-02
  completes with Phase 5's VPC origin.
- The Free plan launches only Free Tier instance types, so the NAT instance is a `t4g.micro`
  (`t4g.nano` is refused at plan time; found in the first window).
- Accepted for dev: single-AZ database and one NAT; Spot interruptions (the service replaces the
  task); TLS ends at the ALB.

## Alternatives considered
- **A single EC2 instance running Compose.** Free-tier-like cost, but none of the managed controls
  (private origin, managed TLS to the database, task-level IAM) Phases 4 and 5 exist to show.
- **`random_password` and `secret_string`.** Simple, and every secret ends up in state.
- **Create the secrets by script outside Terraform.** Also out of state, but a second, unreviewed
  path; the write-only arguments keep it in the plan.
- **ECS Exec for operations.** Convenient, and a shell into a production container; one-off tasks
  and logs cover what is needed.
- **Interface endpoints instead of NAT for ECR, Secrets Manager and Logs.** No egress at all, but
  five endpoints in two zones cost more per hour than the NAT instance (ADR-0025).
- **Compliance-mode Object Lock.** Stronger, but even the account cannot lift it; governance mode
  with no role allowed to bypass it fits a demo account.

## Consequences
- The window's order is fixed by `docs/aws-deploy-window.md`: NAT and the workload on, images
  pushed, roles, migrations, then the API.
- Phase 5 attaches CloudFront through a VPC origin to this ALB, and adds the rule that admits the
  VPC origin to the ALB's security group.
- Creating the first administrator in AWS needs a path that does not print a password into logs;
  Phase 5 settles it with the edge.
