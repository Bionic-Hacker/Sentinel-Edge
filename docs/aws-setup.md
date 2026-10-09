# AWS setup

How SentinelEdge's AWS account is set up, how to sign in from the command line, and how the
Terraform stacks are applied. Only `apply` creates resources that can cost money, and only from a
plan you saved and reviewed. Terraform conventions are in [terraform/README.md](../terraform/README.md).

## The account

SentinelEdge uses an account created through AWS's newer sign-up experience ("Sign up for AWS
(new)", September 2026). The account belongs to a project in an organization that AWS manages
for you, and people sign in with an AWS Builder ID instead of a root user or IAM users. That
changes a few things, all checked on 2026-10-09 with read-only calls:

| Fact | Effect on SentinelEdge |
|---|---|
| The home Region is set at sign-up and cannot be changed: **us-east-2** | Every regional resource lives in us-east-2 |
| us-east-1 is usable (a certificate request there succeeded and was deleted) | CloudFront's certificate and its WAF web ACL, which AWS requires in us-east-1, are created there in Phase 5 |
| AWS writes the organization's guardrail policies (SCPs); custom SCPs are not available | IAM Access Analyzer is denied by one of them, so the account stack does not create it |
| IAM users and roles work for programmatic access only | No IAM password policy and no IAM console-sign-in alarm: nobody signs in that way |
| The CLI signs in with `aws login` (a browser sign-in, 12-hour sessions) | No access keys exist anywhere; `scripts/tf.sh` passes the session to Terraform |
| CloudFront VPC origins, Nova Micro in us-east-2 (and `us.amazon.nova-micro-v1:0`) | Available, as the design (ADR-0001, ADR-0006) needs |

**Cost ceiling.** On the Free plan, usage is paid from the sign-up credits and the account cannot
be billed; when the credits run out you must upgrade. The Free plan ends after six months.
Upgrading to the paid plan carries remaining credits over and lets you set a **monthly spend limit
per project**: a project that reaches it is paused for the rest of the month. Set one when you
upgrade. "Activate advanced features" would remove spend limits, and cannot be undone, so
SentinelEdge does not use it.

## Tools

On Garuda (Arch):

```fish
sudo pacman -S --needed aws-cli-v2 terraform
aws --version
terraform version
```

Terraform 1.10 or later is required (S3 state locking). CI uses 1.15.9. TFLint is optional
locally (`make tf-check` skips it if missing); CI always runs it.

## Signing in

```fish
aws configure set region us-east-2 --profile sentineledge
aws login --profile sentineledge
aws sts get-caller-identity --profile sentineledge
set -gx AWS_PROFILE sentineledge
```

The identity is `assumed-role/AccountFullAccessRole/...` in your project's account. The session
lasts 12 hours; run `aws login --profile sentineledge` again when it expires. Never paste
credentials into chats, issues or files: nothing in this project needs them written down.

`scripts/tf.sh` (behind every `make tf-*` target) refuses to run unless that identity belongs to
the stack's `account_id`, refuses the root user, and hands Terraform the session through its own
environment only.

## Applying the stacks

Order: `bootstrap`, then `account` (then, from Part 2, `dev`). For each stack:

```fish
cp terraform/bootstrap/terraform.tfvars.example terraform/bootstrap/terraform.tfvars
# edit: account_id, and the e-mail address for alerts
make tf-plan STACK=bootstrap
# read the plan: every resource it adds, and "0 to change, 0 to destroy" on a first run
make tf-apply STACK=bootstrap
make tf-lock STACK=bootstrap
```

- `tf-plan` saves the plan; `tf-apply` applies exactly that file and deletes it.
- `tf-lock` records provider checksums for Linux, macOS and CI in `.terraform.lock.hcl`. Commit
  the lock files.
- `bootstrap` keeps its state in `terraform/bootstrap/terraform.tfstate` on your machine
  (git-ignored). It holds names and ARNs only. Keep a copy: losing it means importing the
  resources again, not losing them.
- After `account`, AWS sends a subscription e-mail for the security-alerts topic: confirm it, or
  the alarms have nowhere to go.

## What stays running, and what it costs

| Stack | Billable resources | Standing cost |
|---|---|---|
| `bootstrap` | State KMS key; state and access-log buckets (a few KB) | ≈ $1/month |
| `account` | Platform KMS key; CloudTrail bucket and log group; 4 alarms (always-free tier) | ≈ $1/month |

The deploy window (Phases 4 and 5) adds the hourly resources: see ADR-0016 and the Phase 4 notes.

## Tearing down

Reverse order: `dev`, then `account`, then `bootstrap`, each with `make tf-destroy-plan STACK=…`
and `make tf-apply STACK=…`. The state bucket refuses to be destroyed until `prevent_destroy` is
removed from `terraform/bootstrap/main.tf` on purpose. KMS keys wait 30 days before deletion and
can be recovered until then.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `tf: no usable AWS credentials` | The session expired: `aws login --profile sentineledge`, and check `AWS_PROFILE` is set |
| `tf: signed in to account …, but … may only change …` | The profile points at another account, or `terraform.tfvars` has the wrong `account_id` |
| `explicit deny in a service control policy` | AWS's guardrails block that action in this account. Note the action and stop; do not work around it |
| `state bucket … not found` | Apply `bootstrap` before `account` or `dev` |
| `Error acquiring the state lock` | Another run is in progress, or one was interrupted. If you are sure none is running: `terraform -chdir=terraform/<stack> force-unlock <id>` |
