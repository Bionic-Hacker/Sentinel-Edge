# ADR-0010: CI/CD identity via GitHub OIDC; pinned third-party actions

- **Status:** Accepted (pinning and read-only token in Phase 1; OIDC in Phase 11)
- **Date:** 2026-10-06
- **Phase:** 1, 11

## Decision
- No long-lived AWS keys in GitHub. Workflows assume per-environment IAM roles through OIDC.
  Trust policies pin `aud` and a `sub` scoped to a GitHub *environment*
  (`repo:<org>/<repo>:environment:production`), and production requires reviewer approval.
- `permissions: contents: read` by default; jobs request more only when they need it.
- Third-party actions are pinned to full commit SHAs (tag in a comment); Dependabot proposes
  updates.
- `persist-credentials: false` on checkout.

## Security impact
Mitigates pipeline compromise and supply-chain substitution (T-CICD-01, T-CICD-02).
