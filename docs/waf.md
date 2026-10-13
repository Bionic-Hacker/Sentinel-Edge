# AWS WAF

The web ACL in front of CloudFront (Phase 5, [ADR-0027](adr/0027-cloudfront-waf-and-the-private-origin.md)).
It exists only during a deploy window, with the rest of the edge; between windows nothing is
served. Code: `terraform/modules/waf`.

## Rules

Scope CLOUDFRONT, in us-east-1. Rules are evaluated in priority order; the first terminating
match wins. The default action is allow.

| Priority | Rule (web ACL name) | What it is | Action |
|---|---|---|---|
| 0 | `ip-reputation` | AWS IP reputation list: addresses AWS has seen attacking | Block |
| 1 | `core-rule-set` | AWS core rule set (cross-site scripting, LFI/RFI, bad bots, size limits) | Block; its 8 KB body rule counts only |
| 2 | `known-bad-inputs` | AWS known bad inputs: Log4j and Java deserialisation, exploitable paths | Block |
| 3 | `sql-injection` | AWS SQL injection rule set | Block |
| 10 | `body-too-large` | Request bodies over 64 KB (the inspection limit, raised from 16 KB) | Block |
| 20 | `sign-in-rate` | More than 100 requests to `/api/v1/auth/*` per IP in 5 minutes | Block |
| 21 | `api-rate` | More than 2000 requests to `/api/*` per IP in 5 minutes | Block |

The core rule set's `SizeRestrictions_BODY` (8 KB) is overridden to count: the API accepts up to
1 MB on a few endpoints, and the 64 KB rule is SentinelEdge's own limit. Behind WAF, the app's
own token buckets (ADR-0017) limit per endpoint and per account, and its detect-only HTTP
analysis (Phase 7) records what gets through.

Not adopted: **Bot Control** ($10 a month plus per-request fees while the ACL exists) and
CAPTCHA. Sign-in is covered by the rate rule, the app's per-IP and per-account limits, lockout
and MFA (threat model T-ID-10).

## Logging

Every request WAF evaluates is logged to `aws-waf-logs-<name>` in us-east-1, kept 30 days, with
the `Authorization` and `Cookie` headers redacted. The log doubles as the edge's access log
(CloudFront standard logs would duplicate it without redaction).

The API reads new `BLOCK` records every five minutes and stores each as a **Real AWS** security
event: the WAF page shows blocks by rule, the Threats page lists them next to the platform's own
events, and correlation treats them like any other event (five blocked injections from one address
raise COR-003, one level lower because nothing reached the app). Leads can press **Sync now**.
See [ADR-0029](adr/0029-the-edge-read-back.md).

The API's role may read that one log group and nothing else of WAF.

## Changing a rule

Only through Terraform (ADR-0008):

1. Change `terraform/modules/waf/main.tf` and its tests (`waf.tftest.hcl`).
2. `make tf-check` (tests, TFLint), `make scan` (Checkov).
3. Pull request, review, merge.
4. In a window: `make tf-plan STACK=dev`, read the plan, `make tf-apply STACK=dev`.
5. `make edge-check` must still pass.

The **simulated WAF** on the WAF page (Phase 7) is a separate, labelled simulation: changing a rule
there changes simulations only, never AWS.

## A false positive

A legitimate request blocked shows on the WAF page with its rule. To allow it, scope an exception
in Terraform as narrowly as the rule allows (a `scope_down_statement` on the path, or a rule
action override to count for one managed sub-rule), record it as a security exception in
Compliance with an expiry, and follow the change steps above.

## Evidence

In the first deploy window (12–13 October 2026), `make edge-check` saw an SQL injection and a
Log4j probe blocked at the edge, and within hours of the name going live WAF had blocked 179
scanner probes for exploitable paths (`/.env`, `/.git`, `/wp-login.php`) from the internet.
