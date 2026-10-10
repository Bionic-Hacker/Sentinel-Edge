# ADR-0014: Terraform state and environment isolation

- **Status:** Accepted (implementation in Phase 3)
- **Date:** 2026-10-06

## Decision
- **State:** S3 backend with native lockfiles (`use_lockfile = true`, Terraform ≥ 1.10). Bucket:
  SSE-KMS, versioning, public access blocked, TLS-only bucket policy, access logging. One state
  key per environment. A small `bootstrap/` stack creates it.
- **Per-environment roots:** `backend.tf` and `providers.tf` live inside each
  `environments/<env>/` directory, not at the Terraform root. A shared root backend is the most
  common way development work lands on production state (spec §44).
- **Guards:** each provider sets `allowed_account_ids`; `default_tags` stamp `Environment`; CI
  roles are scoped by OIDC `sub` to their environment.
- **Preferred:** separate AWS accounts per environment. The guards above make single-account use
  safe enough for a portfolio.

## Security impact
Prevents cross-environment changes (T-IAC-01) and state disclosure (state can contain sensitive
values, T-IAC-02).

## Addendum (Phase 3, 2026-10-09): as built
- **Three roots, not a shared one:** `terraform/bootstrap` (the state bucket, its access-log bucket,
  the state key and the budget), `terraform/account` (account-wide guardrails, CloudTrail, alarms,
  the platform key) and `terraform/environments/dev`. Each has its own state key.
- **Bootstrap keeps local state.** It creates the bucket the others use, so its own state lives in
  `terraform/bootstrap/terraform.tfstate` on the owner's machine (git-ignored). It holds names and
  ARNs only; losing it means importing a handful of resources, not losing them.
- **The bucket refuses other keys.** Its policy denies `PutObject` under any KMS key but the state
  key, and any explicit SSE-S3 header; the bucket has `prevent_destroy`.
- **Guards, as built:** `scripts/tf.sh` refuses to run unless the signed-in identity's account is
  the stack's `account_id`, refuses the root user, and applies only a saved, reviewed plan; the
  provider's `allowed_account_ids` refuses again.
- **One account.** All stacks share the project's single account (ADR-0025); `environments/dev` is
  the only environment. Staging and production would be copies with their own state key and,
  ideally, their own account.
