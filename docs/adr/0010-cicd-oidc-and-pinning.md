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

## Addendum (Phase 3, 2026-10-09): OIDC is not available in this account
The project's AWS account (ADR-0025) is managed by AWS's newer sign-up experience, whose
AWS-written service control policies deny `iam:CreateOpenIDConnectProvider`. The GitHub Actions
identity provider therefore cannot be created, and no workflow can assume a role in this account
without stored keys. The rule stands: **no long-lived AWS keys in GitHub**. Until Phase 11 decides
otherwise, Terraform runs from the owner's machine with a 12-hour `aws login` session, and CI runs
only checks that need no AWS access (fmt, validate, module tests, TFLint, Checkov). Phase 11
chooses between a separate account that allows OIDC, a different keyless route, or keeping
deployment off CI.
