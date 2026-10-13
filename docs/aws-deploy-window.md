# The AWS deploy window

How the workload (Phase 4, ADR-0026) and the edge (Phase 5, ADR-0027) are switched on in AWS,
checked and switched off again. One switch, `workload`, brings both. Between windows only free or
near-free resources exist: the network, the DNS zone, the certificates, two empty ECR repositories, the audit-anchor
bucket and two KMS keys (about $2.50 a month).

Everything here runs from your machine, signed in with `aws login` (docs/aws-setup.md), and every
Terraform change is applied only from a plan you read first.

## Cost

| While the window is open | Per hour |
|---|---|
| API task, 0.5 vCPU and 1 GB, on Fargate Spot | ≈ $0.008 |
| Internal ALB | ≈ $0.030 |
| RDS `db.t4g.micro` with 20 GB | ≈ $0.019 |
| NAT instance (`t4g.micro`) and its public address | ≈ $0.013 |
| Secrets, alarms, logs, one-off tasks | ≈ $0.006 |
| AWS WAF: web ACL and 7 rules, prorated | ≈ $0.017 |
| CloudFront, S3, Route 53 queries | free tier |
| **Total** | **≈ $0.09 an hour, $2.20 a day** |

Paid from the sign-up credits; on the Free plan the account cannot be billed.

## Before the first window: once

```fish
make rds-ca                    # Amazon RDS's CA bundle; review and commit it
make check
make tf-check
```

## 1. Switch the network and the workload on

In `terraform/environments/dev/terraform.tfvars`:

```hcl
nat_mode          = "instance"
workload          = true
api_desired_count = 0
```

## 2. Push the images

From a clean, committed tree. This builds the API and dbadmin images for linux/amd64, pushes them
tagged with the commit, and writes their digests to `images.auto.tfvars` (git-ignored):

```fish
make images-push
```

## 3. Plan and apply

```fish
make tf-plan STACK=dev 2>&1 | grep -E "Plan:"
make tf-apply STACK=dev
```

The plan only adds: the NAT instance, the database, secrets, ALB, ECS, the schedule, the alarms,
WAF and the CloudFront distribution with its alias records. RDS takes about ten minutes to
create, CloudFront a few more.

## 4. Roles, then migrations

```fish
make ecs-task TASK=dbadmin
make ecs-task TASK=migrate
```

`dbadmin` ends with `SentinelEdge database roles and schema are in place`; `migrate` with
`Running upgrade 0015 -> 0016`. Each fails loudly on a non-zero exit and prints its log.

## 5. Start the API

Set `api_desired_count = 1`, then:

```fish
make tf-plan STACK=dev 2>&1 | grep -E "Plan:"     # 0 to add, 1 to change
make tf-apply STACK=dev
```

## 6. Publish the SPA and check the edge

```fish
make spa-push
make edge-check
```

Within five minutes the API reads the blocks `edge-check` caused back from the WAF log (ADR-0029):
the **WAF** page shows them as Real AWS, the **Threats** page lists them, and **Certificates** shows
both ACM certificates. Leads can press **Sync now** instead of waiting.

`make edge-check` tests the edge from the internet and must end with `All edge checks passed.`:
HTTP redirected, TLS 1.2 or later, the SPA's headers identical to the local ones, the API ready,
WAF blocking an SQL injection and a Log4j probe, the ALB private and unreachable, and no API under
any other name.

## 7. Create your administrator

```fish
make ecs-task TASK=create-admin EMAIL=you@example.com
```

It prints the AWS command that reads the one-time password, once, from Secrets Manager; the
password is never printed by the task or kept in its log. Sign in at
`https://sentineledge.bionichacker.dev`, set a new password and enroll MFA.

Everyone else is created from Settings → Users, which shows a temporary password once; a
forgotten password is reset there too. Nothing is emailed (ADR-0028).

## 8. Anchor the audit chain

```fish
make ecs-task TASK=anchor
make ecs-task TASK=anchor-check
```

Expect `Anchored seq=…` and `Audit chain matches the anchor`. The schedule then anchors it every
hour while the window is open.

## Switch everything off

In `terraform.tfvars`:

```hcl
nat_mode = "none"
workload = false
```

```fish
make tf-plan STACK=dev 2>&1 | grep -E "Plan:"     # 0 to add, 0 to change, N to destroy
make tf-apply STACK=dev
```

This removes the edge too: WAF, the distribution (it takes several minutes to disable) and the
alias records, so the name stops resolving. The database is deleted without a final snapshot (its
data is synthetic) and the secrets at once, so the next window recreates both. Anchors stay in
their bucket, locked for 30 days.

## When something goes wrong

| Symptom | Cause | Fix |
|---|---|---|
| `The workload needs nat_mode instance or gateway …` | A precondition of the switch | Set `nat_mode`, `dns_delegated` and run `make images-push` |
| `images-push: the working tree has uncommitted changes` | An image must match a commit | Commit, then push the images again |
| A task stops with `CannotPullContainerError` or `ResourceInitializationError` | No NAT, or the secret or image is unreachable | `nat_mode = "instance"`; check the task's stopped reason in the console |
| `dbadmin` fails with `permission denied` | The roles script ran as an unexpected user | Check `PGUSER` comes from the RDS master secret (task definition) |
| The API starts and stops | It refuses its settings in a deployed environment, or cannot verify the database's certificate | `aws logs tail /ecs/sentineledge-dev/api` |
| `make edge-check`: a WAF probe is not blocked | The web ACL is not attached, or a rule is in count mode | `aws wafv2 get-web-acl-for-resource` for the distribution; plan the dev stack again |
| The site shows `502` | CloudFront cannot complete TLS to the ALB, or no healthy task | Check the ALB target health; the API must be running (step 5) |
| `create-admin` exits 2 | `SENTINEL_ADMIN_OTP_SECRET` missing in the task | Re-apply the dev stack (the admin task definition sets it) |
| `audit-anchor check` fails | The newest audit records were removed or changed | Treat as an incident (docs/runbooks); the anchor cannot be altered |
| `RunInstances`: the instance type is not eligible for Free Tier | The Free plan launches only Free Tier types | Keep `nat_instance_type` at `t4g.micro` (the module refuses `t4g.nano`) |
| `CreateBucket` … explicit deny in a service control policy | The Free plan's SCP denies new S3 buckets in us-east-1 | Buckets live in the home Region; the SPA bucket uses the edge module's `aws.home` provider |
| Target health: `Health checks failed with these codes: [400]` | An image older than the liveness-probe Host exemption | `make images-push`, then plan and apply |
| An apply stops partway | One resource failed; the others stay created and billed | Fix, then plan again: the plan adds only what is missing |
| Spend looks wrong | Something hourly survived the window | docs/runbooks/aws-cost-runaway.md |
