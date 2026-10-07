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
