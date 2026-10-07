# ADR-0001: Private origin — internal ALB behind CloudFront VPC origins

- **Status:** Accepted
- **Date:** 2026-10-06
- **Phase:** 4 (ALB), 5 (CloudFront)

## Context
The WAF is attached to CloudFront. If the origin load balancer is internet-reachable, an attacker
who discovers it can bypass CloudFront and the WAF entirely (threat T-EDGE-03). The common
mitigations — restricting the ALB security group to the CloudFront managed prefix list and
requiring a secret custom header — reduce the risk but leave a public endpoint, and the prefix
list admits traffic from *any* CloudFront distribution, including an attacker's.

## Decision
Deploy the Application Load Balancer as **internal** in private subnets and connect it to
CloudFront with **CloudFront VPC origins**. The ALB has no public IP addresses. The ALB security
group admits only the CloudFront VPC-origin service security group. The ALB listener uses HTTPS
with an ACM certificate so the CloudFront→origin hop is encrypted.

Forwarded-for handling: Uvicorn proxy-header trust stays disabled until Phase 4, when it is
enabled for the ALB's subnet range only, so clients cannot spoof `X-Forwarded-For`.

## Security impact
- Removes the origin-bypass path (T-EDGE-03) instead of mitigating it. Control C-EDGE-02.
- No public IPv4 on the origin also removes a reconnaissance target.

## Alternatives considered
- **Public ALB + prefix list + secret header.** Documented in `docs/cdn-security.md` (Phase 5) as
  the fallback pattern; rejected as primary because the endpoint remains public.
- **API Gateway or Lambda function URLs.** Rejected: the spec requires ECS/Fargate behind an ALB.

## Consequences
- Requires NAT (or VPC endpoints) for task egress, since nothing in the VPC is public except NAT.
- Validation in Phase 5 must prove the ALB is unreachable from the internet.
