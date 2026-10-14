# ADR-0030: CI never touches AWS; a gated deploy from the owner's machine

- **Status:** Accepted
- **Date:** 2026-10-14
- **Phase:** 11
- **Decided by:** Bionic-Hacker (project owner)
- **Supersedes:** the OIDC part of ADR-0010
- **Builds on:** ADR-0010 (no long-lived keys), ADR-0014 (saved plans), ADR-0020 (scan gate),
  ADR-0025 (the account), ADR-0026 and ADR-0027 (the deploy window)

## Context
The specification's pipeline ends in "push to ECR, Terraform plan, deploy, DAST, post-deployment
validation", reached from CI through GitHub OIDC. The account's AWS-written service control
policies deny creating an OIDC provider (ADR-0010 addendum). The alternatives that remain all put
some standing access to AWS where CI can reach it.

## Decision
**CI holds no AWS credential of any kind.** On every push and pull request it runs everything that
needs none: lint, types, tests with coverage, SAST, SCA, secret scanning over all history, IaC
scanning, Terraform format, validate and module tests against a mocked provider, container builds
and scans, SBOMs, authenticated DAST against the stack started in the runner, and the scan gate.

**Deployment is a gated command on the owner's machine** (`scripts/deploy.sh`, ADR-0014's saved
plans underneath):

| Step | Command | Gate |
|---|---|---|
| Preflight | `make deploy-check` | main, a clean tree, HEAD equal to `origin/main`, and **every** check run GitHub recorded for that commit completed successfully; none, pending or failed refuses |
| Build and plan | `make deploy` | preflight again; images built from the commit and pinned by digest; the plan saved for a person to read |
| Apply and verify | `make deploy-finish` | preflight again; applies only the saved plan; migrations; the SPA; then `edge-check` and an audit-anchor check |

The CI results are read from GitHub's public API, with no token. The scan gate's threshold is
configurable (`SCAN_BLOCK_AT`: critical, high by default, or medium), and a non-default threshold
is printed on every run.

**Credentials refresh during long applies.** `scripts/tf.sh` hands Terraform a temporary AWS
config whose profile asks the CLI for fresh `aws login` credentials when the old ones expire
(`credential_process`), after an apply outlived exported 15-minute credentials in the second
deploy window.

## Security impact
- T-CICD-01 (stolen long-lived cloud keys from CI): no key exists to steal, in CI or anywhere.
- A compromised workflow, action or pull request cannot reach AWS: the most it can do is fail a
  check, which then blocks deployment.
- Nothing undeployed or unreviewed reaches AWS: only the tip of main, with green CI, from a plan
  a person read.
- Accepted: deployment needs the owner's machine and sign-in; there is no unattended deploy.

## Alternatives considered
- **A read-only IAM key in GitHub secrets for plans.** Real plans in pull requests, but a stored
  long-lived key, the thing ADR-0010 exists to avoid; and read access to state is itself
  sensitive.
- **A self-hosted runner on the owner's machine.** Full deploys from CI, but the machine would run
  workflow code from pull requests and must be on whenever CI runs.
- **Revisit when the account allows OIDC.** Leaving the Free plan would allow it, but that change
  cannot be undone (ADR-0025). If it happens, a deploy job assuming an OIDC role replaces the
  owner's machine in the table above, and the gates stay the same.
