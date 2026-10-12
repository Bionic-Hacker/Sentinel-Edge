# The AWS deploy window

How the workload (Phase 4) is switched on in AWS, checked and switched off again (ADR-0026).
Phase 5 adds the edge steps to this page. Between windows only free or near-free resources
exist: the network, the DNS zone, the certificates, two empty ECR repositories, the audit-anchor
bucket and two KMS keys (about $2.50 a month).

Everything here runs from your machine, signed in with `aws login` (docs/aws-setup.md), and every
Terraform change is applied only from a plan you read first.

## Cost

| While the window is open | Per hour |
|---|---|
| API task, 0.5 vCPU and 1 GB, on Fargate Spot | ≈ $0.008 |
| Internal ALB | ≈ $0.030 |
| RDS `db.t4g.micro` with 20 GB | ≈ $0.019 |
| NAT instance and its public address | ≈ $0.009 |
| Secrets, alarms, logs, one-off tasks | ≈ $0.006 |
| **Total** | **≈ $0.07 an hour, $1.70 a day** |

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

The plan only adds: the NAT instance, the database, secrets, ALB, ECS, the schedule and the
alarms. RDS takes about ten minutes to create.

## 4. Roles, then migrations

```fish
make ecs-task TASK=dbadmin
make ecs-task TASK=migrate
```

`dbadmin` ends with `SentinelEdge database roles and schema are in place`; `migrate` with
`Running upgrade 0013 -> 0014`. Each fails loudly on a non-zero exit and prints its log.

## 5. Start the API

Set `api_desired_count = 1`, then:

```fish
make tf-plan STACK=dev 2>&1 | grep -E "Plan:"     # 0 to add, 1 to change
make tf-apply STACK=dev
```

## 6. Check it

```fish
set out (./scripts/tf.sh dev output-json)
set cluster (echo $out | python3 -c 'import json,sys; print(json.load(sys.stdin)["workload"]["value"]["cluster"])')
aws ecs wait services-stable --cluster $cluster --services api
aws ecs describe-services --cluster $cluster --services api --query 'services[0].[runningCount,desiredCount]' --output text
make ecs-task TASK=anchor
make ecs-task TASK=anchor-check
```

Expect `1 1`, then `Anchored seq=…` and `Audit chain matches the anchor`. The ALB is internal: it is
reached from the internet only through CloudFront (Phase 5).

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

The database is deleted without a final snapshot (its data is synthetic) and the secrets at once,
so the next window recreates both. Anchors stay in their bucket, locked for 30 days.

## When something goes wrong

| Symptom | Cause | Fix |
|---|---|---|
| `The workload needs nat_mode instance or gateway …` | A precondition of the switch | Set `nat_mode`, `dns_delegated` and run `make images-push` |
| `images-push: the working tree has uncommitted changes` | An image must match a commit | Commit, then push the images again |
| A task stops with `CannotPullContainerError` or `ResourceInitializationError` | No NAT, or the secret or image is unreachable | `nat_mode = "instance"`; check the task's stopped reason in the console |
| `dbadmin` fails with `permission denied` | The roles script ran as an unexpected user | Check `PGUSER` comes from the RDS master secret (task definition) |
| The API starts and stops | It refuses its settings in a deployed environment, or cannot verify the database's certificate | `aws logs tail /ecs/sentineledge-dev/api` |
| `audit-anchor check` fails | The newest audit records were removed or changed | Treat as an incident (docs/runbooks); the anchor cannot be altered |
| Spend looks wrong | Something hourly survived the window | docs/runbooks/aws-cost-runaway.md |
