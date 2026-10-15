# Disaster recovery

What can be lost, how it is restored, and how long that takes (Phase 12). All platform data is
synthetic, so recovery is about the platform working again with its evidence intact, not about
customer data.

## What exists, and where it is kept

| Asset | Where | Protection | Restore |
|---|---|---|---|
| Source, history, tags | GitHub; every clone; signed tags | Branch protection, signed tags, bundles with checksums | Clone, or fetch any delivered bundle |
| Infrastructure | Terraform in git; state in S3 | State bucket versioned, KMS, `prevent_destroy`, native locking | `make tf-plan` / `make tf-apply` from a clean checkout; an older state version from S3 versioning |
| Database (AWS) | RDS, during a deploy window only | One day of automated backups; recreated fresh each window by design | Point-in-time restore inside the window; otherwise a new window starts empty (`dbadmin`, `migrate`, `create-admin`) |
| Database (local) | Docker volume | None beyond the machine | `make dev` recreates it; data is synthetic |
| Audit-chain anchors | S3 Object Lock, governance mode, 30 days | Locked; the anchor role cannot delete or shorten retention | Read back with `anchor-check`; they are the evidence, not a restore source |
| Images | ECR, immutable tags, by digest | Scan on push, KMS | `make images-push` rebuilds any commit |
| Secrets | Secrets Manager, generated per window | Never in plan, state or logs | A new window generates new ones; nothing to restore |
| DNS zone, CAA, certificates | Route 53, ACM | `prevent_destroy`; ACM auto-renewal | Terraform; ACM reissues through the validation record |

## Objectives

| Scenario | RTO (back in service) | RPO (data lost) |
|---|---|---|
| The API or a task fails | Minutes: the ECS service replaces the task | None |
| A bad release | One pipeline run (~20 minutes): revert on main, `make deploy`, `make deploy-finish` | None |
| The database is lost in a window | ~30 minutes: point-in-time restore, or a fresh database | Up to 5 minutes (PITR); synthetic data otherwise |
| The whole environment is lost | One deploy window (~45 minutes from `workload = true`) | The window's synthetic data |
| Terraform state is corrupted | ~15 minutes: restore the previous object version | None; plans show any drift |
| The owner's machine is lost | Hours: a new machine, `aws login`, a clone; nothing secret lived only there | None (`.env` is regenerated; local data is synthetic) |

## Exercised

Every deploy window is a full rebuild from nothing but git and the state bucket: two so far
(12–13 and 13–14 October 2026), each ending with everything destroyed. The second recovered a
partially applied state after expired credentials (`terraform state push`, then `untaint`),
recorded in `claude/phase5-status.md` and the lessons learned.
