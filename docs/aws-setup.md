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
| AWS writes the organization's guardrail policies (SCPs); custom SCPs are not available | They deny IAM Access Analyzer and creating an OIDC identity provider, so the account stack creates neither. Without an OIDC provider, GitHub Actions cannot assume a role here: Phase 11 must revisit ADR-0010 |
| IAM users and roles work for programmatic access only | No IAM password policy and no IAM console-sign-in alarm: nobody signs in that way |
| The CLI signs in with `aws login` (a browser sign-in, 12-hour sessions) | No access keys exist anywhere; `scripts/tf.sh` passes the session to Terraform |
| CloudFront VPC origins are available; Nova Micro is offered in us-east-2 only through the US inference profile `us.amazon.nova-micro-v1:0` | The design (ADR-0001) holds; the AI engine's default model becomes the profile ID, and its role allows the model only through that profile |

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

Order: `bootstrap`, then `account`, then `dev`. For each stack:

```fish
cp terraform/bootstrap/terraform.tfvars.example terraform/bootstrap/terraform.tfvars
# edit: account_id, and the e-mail address for alerts
make tf-plan STACK=bootstrap
# read the plan: every resource it adds, and "0 to change, 0 to destroy" on a first run
make tf-apply STACK=bootstrap
```

- `tf-plan` saves the plan; `tf-apply` applies exactly that file and deletes it.
- `init` writes `.terraform.lock.hcl` with HashiCorp's signed checksums for every platform; commit
  it. `tf-lock` adds package hashes for Linux and Apple silicon, if you ever need them.
- `bootstrap` keeps its state in `terraform/bootstrap/terraform.tfstate` on your machine
  (git-ignored). It holds names and ARNs only. Keep a copy: losing it means importing the
  resources again, not losing them.
- After `account`, AWS sends a subscription e-mail for the security-alerts topic: confirm it, or
  the alarms have nowhere to go.

## The dev environment and its domain

`dev` is the environment's foundation: a VPC across two Availability Zones (pinned by zone ID,
`use2-az1` and `use2-az2`) with public, app and isolated data subnets, flow logs, a free S3
gateway endpoint, the ALB → app → database security-group chain, an ECR repository for the API
image, the platform's DNS zone, and two ACM certificates for the platform's name (one in us-east-1
for CloudFront, one in us-east-2 for the internal ALB). All of it is free while idle except the zone
($0.50 a month).

**NAT** is the one hourly item, switched by `nat_mode` in `terraform/environments/dev/terraform.tfvars`:

| `nat_mode` | Egress for the app tier | Cost |
|---|---|---|
| `none` (default) | None: the resting state between deploy windows | $0 |
| `instance` | One t4g.nano NAT instance (IMDSv2, encrypted, no SSH, no role) | ≈ $0.009/hour |
| `gateway` | One managed NAT gateway | ≈ $0.05/hour |

**The domain** (ADR-0025). The owner's domain, `bionichacker.dev`, is registered at Porkbun and
its DNS stays there. Only the platform's name, `sentineledge.bionichacker.dev` (`app_domain`), is
delegated to a Route 53 zone that `dev` creates. Other projects can take their own names under the
same domain without touching this one. `.dev` is on the browsers' HSTS preload list, so every name
under it is served over HTTPS only.

Terraform publishes everything inside the zone: CAA at its apex (`0 issue "amazon.com"`,
`0 issuewild ";"`: only Amazon may issue, and no wildcards) and the certificates' validation
CNAME. The only manual step is the delegation, once:

1. Plan and apply `dev`. The zone, both certificates and the validation record are created; the
   certificates wait in `PENDING_VALIDATION`.
2. Print the delegation:

   ```fish
   make tf-output STACK=dev 2>&1 | grep -A 12 dns_delegation
   ```

3. At Porkbun, open the domain's **DNS** records and add four records, one per name server:
   type `NS`, host `sentineledge`, answer the name server (for example
   `ns-123.awsdns-15.com`), TTL 3600. Change nothing else; the domain's own name servers stay
   Porkbun's.
4. Check the delegation from your machine (all four servers, and the CAA through them):

   ```fish
   dig +short NS sentineledge.bionichacker.dev
   dig +short CAA sentineledge.bionichacker.dev
   ```

5. Within minutes ACM issues both certificates. Set `dns_delegated = true` in
   `terraform/environments/dev/terraform.tfvars`, plan and apply `dev` again: Terraform waits for
   both certificates to be `ISSUED` (it adds two waiting resources and creates nothing billable),
   and Phase 5 builds on that.

A certificate request not validated within 72 hours expires. Re-apply `dev`; the record is the
same, so the new request validates as soon as the delegation is live.

## What stays running, and what it costs

| Stack | Billable resources | Standing cost |
|---|---|---|
| `bootstrap` | State KMS key; state and access-log buckets (a few KB) | ≈ $1/month |
| `account` | Platform KMS key; CloudTrail bucket and log group; 4 alarms (always-free tier) | ≈ $1/month |
| `dev` (`nat_mode = "none"`) | Flow-log group; empty ECR repository; Route 53 zone; certificates are free | ≈ $0.50/month |

The deploy window (Phases 4 and 5) adds the hourly resources: see ADR-0016 and the Phase 4 notes.

## Tearing down

Reverse order: `dev`, then `account`, then `bootstrap`, each with `make tf-destroy-plan STACK=…`
and `make tf-apply STACK=…`. The state bucket refuses to be destroyed until `prevent_destroy` is
removed from `terraform/bootstrap/main.tf` on purpose. KMS keys wait 30 days before deletion and
can be recovered until then.

**The DNS zone first.** `dev` refuses to delete its zone (`prevent_destroy`), because a zone deleted
while Porkbun still delegates to its name servers can be claimed by anyone who creates zones until
Route 53 hands them the same servers. Delete the four `sentineledge` NS records at Porkbun, wait an
hour (their TTL), then remove `prevent_destroy` from `terraform/modules/dns-zone/main.tf` and
destroy `dev`.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `tf: no usable AWS credentials` | The session expired: `aws login --profile sentineledge`, and check `AWS_PROFILE` is set |
| `tf: signed in to account …, but … may only change …` | The profile points at another account, or `terraform.tfvars` has the wrong `account_id` |
| `explicit deny in a service control policy` | AWS's guardrails block that action in this account. Note the action and stop; do not work around it |
| `state bucket … not found` | Apply `bootstrap` before `account` or `dev` |
| `Error acquiring the state lock` | Another run is in progress, or one was interrupted. If you are sure none is running: `terraform -chdir=terraform/<stack> force-unlock <id>` |
