# Terraform

SentinelEdge's AWS infrastructure. Writing and checking it costs nothing; only `apply` creates
billable resources, and only from a plan that has been saved and reviewed. Setup, credentials and
the deploy window are in [docs/aws-setup.md](../docs/aws-setup.md). The decisions are in
[ADR-0014](../docs/adr/0014-terraform-state-and-environment-isolation.md) (state and isolation)
and [ADR-0016](../docs/adr/0016-local-first-phase-order.md) (when AWS money is spent).

## Stacks

| Stack | Path | State | Holds | Standing cost |
|---|---|---|---|---|
| `bootstrap` | `bootstrap/` | Local file (it creates the bucket the others use) | State bucket, access-log bucket, state KMS key, cost budget | ≈ $1/month (the key) |
| `account` | `account/` | S3, key `account/terraform.tfstate` | Account guardrails, CloudTrail, security alarms, platform KMS key | ≈ $1/month (the key) |
| `dev` | `environments/dev/` | S3, key `dev/terraform.tfstate` | VPC and subnets, flow logs, S3 endpoint, security-group chain, ECR, certificates; NAT behind `nat_mode` | ≈ $0 with `nat_mode = "none"`; the deploy window is billed by the hour |

Apply in that order. Destroy in the reverse order; `bootstrap`'s state bucket refuses to be
destroyed until `prevent_destroy` is removed on purpose.

## Rules

- **No credentials, secrets or real `*.tfvars` in git.** Each stack has a
  `terraform.tfvars.example`; the real file is git-ignored, as are saved plans and `backend.hcl`.
  Gitleaks scans every commit.
- **One account per stack, checked twice.** `scripts/tf.sh` refuses to run unless the signed-in
  identity belongs to the stack's `account_id` (and refuses the root user); the provider's
  `allowed_account_ids` refuses again.
- **Plan, review, apply the saved plan.** `make tf-plan STACK=…` saves `tfplan`;
  `make tf-apply STACK=…` applies only that file. There is no auto-approve.
- **Remote state is encrypted and locked.** SSE-KMS under the state key (the bucket refuses any
  other key), versioned, TLS-only, access-logged, with S3-native locking (`use_lockfile`).
- **Pinned providers.** `~> 6.66` in each stack; the committed lock files hold HashiCorp's signed
  checksums for every platform, so `init` verifies the same binaries everywhere.
- **Tested and scanned before it is applied.** `make tf-check` (fmt, validate, module tests
  with a mocked AWS provider, TFLint) and Checkov in
  `make scan` and CI. Checkov exceptions are written in place as
  `# checkov:skip=<id>: <reason>`.

## Layout

```
terraform/
├── .tflint.hcl
├── bootstrap/          # state bucket, access logs, state key, budget (local state)
├── account/            # guardrails, CloudTrail, alarms, platform key
├── modules/            # network, security-groups, ecr, certificate (each tested with
│                       # terraform test and a mocked provider)
└── environments/
    └── dev/            # the one environment; staging and production would be copies with
                        # their own backend key, tfvars and, ideally, their own account
```
