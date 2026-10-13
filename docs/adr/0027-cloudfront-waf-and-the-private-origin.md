# ADR-0027: The edge as built: CloudFront, a VPC origin, WAF, and the same headers as locally

- **Status:** Accepted (built and tested without AWS; applied in the Phase 4–5 deploy window)
- **Date:** 2026-10-12
- **Phase:** 5
- **Decided by:** Bionic-Hacker (project owner)
- **Builds on:** ADR-0001 (private origin), ADR-0002 (one origin, no CORS), ADR-0004 (two-layer
  rate limiting), ADR-0008 (WAF only through Terraform), ADR-0011 (headers at the edge and in the
  app), ADR-0025 (domain), ADR-0026 (workload)

## Context
Phase 4 left the API behind an internal ALB that nothing outside the VPC can reach. Phase 5 is the
only way in: CloudFront for `sentineledge.bionichacker.dev`, AWS WAF in front of it, the SPA from
S3. Locally nginx plays this role, and the edge must behave the same way: one origin for pages and
API, the same security headers, client-side routes served by `index.html`. It is created and
removed with the workload in each deploy window.

## Decision

**One distribution, two origins.**
- `/api/*` goes through a **CloudFront VPC origin** to the internal ALB, over HTTPS only (TLS 1.2).
  The viewer's Host header is forwarded (managed AllViewer policy), so the origin certificate and
  the ALB's host rule both match the platform's name; under any other name, including the
  distribution's own `*.cloudfront.net`, the API is not served. Responses are never cached.
- Everything else comes from a **private S3 bucket through Origin Access Control**, in the home
  Region (the Free plan's service control policy denies creating buckets in us-east-1): public access
  blocked, and the bucket policy lets only this distribution read it. A CloudFront Function routes
  paths without a file extension to `index.html`, as nginx's `try_files` does. It runs only on the
  default behaviour, never on `/api/*`.
- Viewers: TLS 1.2 or later (`TLSv1.2_2021`), HTTP redirected for pages and refused for the API,
  HTTP/2 and HTTP/3, A and AAAA aliases at the zone apex.

**The ALB admits only CloudFront.** AWS creates the security group
`CloudFront-VPCOrigins-Service-SG` in the VPC with the first VPC origin; the ALB's only ingress rule
references it.

**Headers identical to the local edge.** The SPA's response-headers policy is generated from one
map that a test compares, header for header, with `frontend/security-headers.conf`
(`test_edge_headers_match_nginx`): CSP, HSTS, nosniff, frame and referrer options, the permissions
policy and cross-origin isolation. On `/api/*` the API's own stricter headers stand; the edge adds
HSTS and nosniff only if missing. HSTS omits `preload`: the whole `.dev` TLD is preloaded.

**AWS WAF** (CLOUDFRONT scope, us-east-1), first match wins:

| Priority | Rule | Action |
|---|---|---|
| 0 | AWS IP reputation list | Block |
| 1 | AWS core rule set (its 8 KB body rule counts) | Block |
| 2 | AWS known bad inputs (Log4j and others) | Block |
| 3 | AWS SQL injection | Block |
| 10 | Body over 64 KB (the inspection limit, raised from 16 KB) | Block |
| 20 | `/api/v1/auth/*`: more than 100 requests per IP in 5 minutes | Block |
| 21 | `/api/*`: more than 2000 requests per IP in 5 minutes | Block |

The app's own limiter (ADR-0017) stays behind it, per account and per endpoint. Every request WAF
evaluates is logged to `aws-waf-logs-…` in us-east-1 for 30 days, with `Authorization` and `Cookie`
redacted; that log also serves as the edge's access log. The application has no WAF permissions at
all.

**Timeouts.** CloudFront waits at most 60 seconds for an origin without a quota increase. The
API's AI timeout in AWS is 25 seconds, so its two attempts fit.

**The first administrator.** Locally `create-admin` prints a one-time password. In AWS that would
put a credential in the task's log for a year, so a deployed environment refuses to print it: the
admin task writes it to one Secrets Manager secret, which its role can write but not read, and
the owner reads it once with the AWS CLI. The password must be replaced, and MFA enrolled, at first
sign-in.

**Tooling.** `make spa-push` publishes a build from a committed tree (hashed assets immutable,
everything else `no-cache`, stale files removed, `index.html` invalidated). `make edge-check`
proves the edge from the internet: redirects, TLS, headers, readiness, WAF blocking an SQL injection
and a Log4j probe, a private and unreachable ALB, no API under another name.

## Security impact
- Mitigates (once verified in the window) T-EDGE-01 to T-EDGE-04, T-EDGE-06 at the edge, T-EDGE-07
  and T-EDGE-08 (new), T-WAF-01, T-WAF-02, T-SEC-03 (new), and completes T-EDGE-03 with ADR-0026.
- Controls C-EDGE-01, C-EDGE-03, C-EDGE-04 (new), C-WAF-01 to C-WAF-04, C-EDGE-02 completed.
- Accepted: the SPA bucket uses SSE-S3 (public content); WAF logs use CloudWatch's own key and
  are kept 30 days; no geographic restriction; no origin failover.

## Alternatives considered
- **A public ALB with a secret header from CloudFront.** The common pattern, but the ALB would be
  reachable from the internet, and a leaked header defeats it. The VPC origin removes the public
  address altogether.
- **Custom error responses mapping 403/404 to `index.html`.** Simpler, but they apply to every
  origin and would turn API errors into the SPA's HTML. The function touches only page routes.
- **CloudFront standard logs.** They duplicate WAF's log without redaction.
- **Keeping the distribution between windows.** Free when idle, but its VPC origin needs the ALB,
  and WAF is billed monthly; both come and go with the workload.
- **Printing the administrator's password and deleting the log stream.** Relies on remembering to
  delete it; the secret makes the safe way the only way.

## Consequences
- The window adds `make spa-push`, `make ecs-task TASK=create-admin` and `make edge-check` to
  `docs/aws-deploy-window.md`.
- Evidence for the release comes from `make edge-check` and the WAF log.
