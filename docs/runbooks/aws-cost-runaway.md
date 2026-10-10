# Runbook: AWS cost runaway, or a deploy window left running

- **Severity guidance:** SEV2: spend above the $30 budget, or billable resources running with nobody
  using them for more than a day. SEV3: a budget alert at $5 or $15 during a planned deploy window
  (the expected case: check it matches the plan). SEV1 is not expected: on the Free plan the account
  cannot be billed beyond its credits.
- **Owner role:** the project owner (the only person with AWS access)
- **Related threats / controls:** T-COST-01, T-AWS-03, T-AI-06; C-COST-01, C-AI-06, C-MON-02;
  ADR-0016, ADR-0025
- **Last exercised:** not yet. The first deploy window (Phases 4 and 5) exercises the teardown.

## 1. Detection
- **E-mail from AWS Budgets:** "sentineledge-monthly" actual spend above $5, $15 or $30, or a
  forecast above $30.
- **AWS Settings, or Billing:** credits falling faster than the window's plan (about $3 a day).
- **Terraform:** `make tf-output STACK=dev` shows `nat_mode` other than `none` outside a window.

## 2. Triage (first 15 minutes)
1. Is a deploy window planned and running? If yes, compare the spend with the plan (NAT instance
   about $0.009/hour; the whole window about $3 a day). In line: record it and stop here.
2. If no window is running, list what bills by the hour:
   ```fish
   aws ec2 describe-nat-gateways --region us-east-2 --filter Name=state,Values=available --query 'NatGateways[].NatGatewayId'
   aws ec2 describe-instances --region us-east-2 --filters Name=instance-state-name,Values=running --query 'Reservations[].Instances[].[InstanceId,InstanceType,Tags[?Key==`Name`]|[0].Value]'
   aws ec2 describe-addresses --region us-east-2 --query 'Addresses[].[PublicIp,AssociationId]'
   aws elbv2 describe-load-balancers --region us-east-2 --query 'LoadBalancers[].LoadBalancerName'
   aws rds describe-db-instances --region us-east-2 --query 'DBInstances[].DBInstanceIdentifier'
   ```
3. Anything listed that Terraform does not know about (not tagged `ManagedBy = Terraform`) is a
   security question, not only a cost one: go to step 3 of Investigation before deleting it.

## 3. Investigation
- **Cost Explorer, by service and day:** which service, since when.
- **CloudTrail** (`/aws/cloudtrail/sentineledge-account`): who created the resource, from where.
  A creator other than your own `aws login` session means the account is compromised: treat it as
  an incident, follow your incident process, and keep the evidence before tearing down.
- **Bedrock spend:** the AI quotas (C-AI-06) bound it to cents a day; a larger figure means the
  quotas were raised or something else is calling the model.

## 4. Containment
| What is running | Stop it with |
|---|---|
| NAT (instance or gateway) | Set `nat_mode = "none"` in `terraform/environments/dev/terraform.tfvars`, then `make tf-plan STACK=dev` and `make tf-apply STACK=dev` |
| The Phase 4 and 5 workload | `make tf-destroy-plan STACK=dev`, review, `make tf-apply STACK=dev` |
| Something Terraform does not manage | Stop or delete it in the console after recording what it is |
| Unexplained Bedrock use | `make bedrock-credentials-clear`; set `SENTINEL_AI_PROVIDER=offline` |

On the paid plan, setting the project's spend limit low pauses the whole project immediately.

## 5. Remediation
- A forgotten window: add a reminder at the end of the next window, and check the destroy list in
  step 2 is empty afterwards.
- An unexpected billable resource in a module: add a module test that `nat_mode = "none"` (or the
  module's equivalent) creates no hourly resource.

## 6. Validation
1. The step 2 commands list nothing (or only what the plan says should be running).
2. `make tf-plan STACK=dev` shows no changes.
3. The next day's spend in Cost Explorer is the standing cost only (about $2 a month).

## 7. Rollback
- Nothing to roll back: the environment is re-created with `make tf-plan STACK=dev` and
  `make tf-apply STACK=dev`. Certificates, the registry and the state are kept.

## 8. Post-incident
- Record the cause and the fix, and update the deploy-window checklist if a step was missed.
