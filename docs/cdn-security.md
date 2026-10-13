# CloudFront and the private origin

How requests reach SentinelEdge in AWS (Phase 5,
[ADR-0027](adr/0027-cloudfront-waf-and-the-private-origin.md), building on
[ADR-0001](adr/0001-private-origin-cloudfront-vpc-origin.md) and
[ADR-0002](adr/0002-single-origin-routing.md)). Code: `terraform/modules/edge`. Like the WAF, it
exists only during a deploy window.

```
Browser ──HTTPS──▶ CloudFront (us-east-1 certificate, TLSv1.2_2021, HTTP/2 and HTTP/3)
                   │  AWS WAF web ACL evaluated first
                   ├── /api/*  ──VPC origin, HTTPS──▶ internal ALB (no public address) ──▶ ECS tasks
                   └── /*      ──OAC──▶ private S3 bucket (the SPA), spa-router function
```

## One origin, two behaviours

| | `/api/*` | everything else |
|---|---|---|
| Origin | CloudFront **VPC origin** to the internal ALB, HTTPS only, TLS 1.2 | Private S3 bucket through **Origin Access Control** |
| Viewer protocol | HTTPS only (HTTP refused) | HTTP redirected to HTTPS |
| Methods | All | GET, HEAD |
| Cache | Never (`CachingDisabled`); the API also sends `Cache-Control: no-store` | `CachingOptimized`: hashed assets for a year, everything else `no-cache` (set by `make spa-push`) |
| Request forwarded | Every viewer header, Host included (`AllViewer`) | None |
| Response headers | The API's own stricter set; the edge adds HSTS and `nosniff` only if missing | A policy identical to `frontend/security-headers.conf` |
| Function | None | `spa-router`: paths without a file extension get `index.html` (client-side routes) |

## Why there is no origin to bypass

- The ALB is **internal**: it has no public address. Its only ingress rule admits the security
  group AWS creates for CloudFront's VPC origins (`CloudFront-VPCOrigins-Service-SG`). There is no
  shared-secret header to leak.
- The **host name** is forwarded, so the ALB's certificate and its host rule both match only
  `sentineledge.bionichacker.dev`. Under the distribution's own `*.cloudfront.net` name the API is
  not served: CloudFront cannot complete TLS to the origin, or the ALB answers 404.
- The **SPA bucket** blocks public access; its policy lets only this distribution read it
  (`AWS:SourceArn`). It lives in the home Region: the account's guardrails deny creating buckets in
  us-east-1.

## Headers

The SPA's response-headers policy is generated from one map that a test compares header for
header with the local nginx (`test_edge_headers_match_nginx`): CSP, HSTS (two years, no `preload`;
the `.dev` TLD is preloaded anyway), `nosniff`, frame and referrer options, the permissions policy
and cross-origin isolation. See [security-headers.md](security-headers.md).

## Timeouts

CloudFront waits at most 60 seconds for an origin without a quota increase. The API's AI timeout
in AWS is 25 seconds, so its two attempts fit.

## Proving it

`make edge-check` tests the edge from the internet (21 checks): HTTP redirected, TLS 1.2 or later,
every SPA header identical to the local one, client-side routes served, the API ready with its own
CSP, WAF blocking an SQL injection and a Log4j probe, the ALB private and unreachable, and no API
under any other name. All passed in the first deploy window.

## Not done

- No geographic restriction and no origin failover (one Region, one ALB).
- A DAST scan of the live edge moves to the Phase 12 deploy window.
