# AWS cost

What SentinelEdge costs in AWS, what runs when, and how to make sure nothing is left running.
Standing costs and the account's budget: [aws-setup.md](aws-setup.md). The window itself:
[aws-deploy-window.md](aws-deploy-window.md). If spend looks wrong:
[runbooks/aws-cost-runaway.md](runbooks/aws-cost-runaway.md).

## Between windows (always)

| Resource | Cost |
|---|---|
| Two KMS keys (platform, state) | $2 a month |
| Route 53 zone | $0.50 a month |
| Route 53 query logs (CloudWatch, us-east-1) | cents |
| VPC, subnets, security groups, flow logs (no traffic) | free to cents |
| Two certificates (ACM) | free |
| Two ECR repositories (images kept) | cents |
| Audit-anchor bucket (Object Lock, 30 days) | cents |
| CloudTrail, alarms, budget | free tier |

About $2.50 a month, paid from the sign-up credits; on the Free plan the account cannot be billed.

## During a window

About **$0.09 an hour**: Fargate Spot (0.5 vCPU, 1 GB), the internal ALB, RDS `db.t4g.micro`,
the NAT instance (`t4g.micro`) and its address, AWS WAF (prorated), secrets, logs and alarms.
CloudFront, S3 and Route 53 queries stay within the free tier at demo volumes.

The first window (Phases 4 and 5, 12–13 October 2026) ran about 36 hours, a few dollars of
credit, including a night left on while waiting.

## Destroy checklist

1. `nat_mode = "none"`, `workload = false`, `api_desired_count = 0` in `terraform.tfvars`.
2. `make tf-plan STACK=dev`: only destroys (93 in the first window).
3. `make tf-apply STACK=dev`; CloudFront takes several minutes to disable.
4. The outputs show `nat_mode = "none"` and no workload outputs.
5. Next day: Billing → Bills shows no new hourly charges.

Watch for: an apply that stops partway (re-plan; the plan lists what is left), a distribution
left disabled but not deleted, an Elastic IP without an instance.
