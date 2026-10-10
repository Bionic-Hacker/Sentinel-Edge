# ADR-0025: The AWS account, the domain and the deploy window, as built

- **Status:** Accepted
- **Date:** 2026-10-09
- **Phase:** 3 (and the constraints it sets for 4, 5 and 11)
- **Decided by:** Bionic-Hacker (project owner)
- **Builds on:** ADR-0001 (private origin), ADR-0010 (CI identity), ADR-0014 (Terraform state),
  ADR-0016 (local-first order)

## Context
Phase 3 is the first phase that creates AWS resources, so it had to settle what the account is,
which name the platform will be served under, and how the spend stays near zero for a portfolio.
Three facts emerged while building it:

- **The account.** The owner created a new account through AWS's newer sign-up experience
  (September 2026). It is a project in an organization that AWS manages: people sign in with an
  AWS Builder ID, there is no root user to use, the home Region (us-east-2) is fixed, and
  AWS-written service control policies apply. Checked with read-only calls and one
  create-and-delete: us-east-1 can be used (CloudFront's certificate and WAF must live there), but
  IAM Access Analyzer and `iam:CreateOpenIDConnectProvider` are denied.
- **The domain.** A TLS certificate needs a name the owner controls, and the owner asked for a free
  one. A Render or other platform subdomain cannot be validated by ACM.
- **The cost.** An always-on dev environment is about $110 a month (ADR-0016), almost all of it
  NAT, the load balancer, the database and WAF.

## Decision

**Stay in the new sign-up experience; do not "activate advanced features".** It would unlock
custom SCPs and Access Analyzer, but it is irreversible and removes per-project spend limits. The
account's credits (Free plan) are a hard spending ceiling: the account cannot be billed, only
stopped. On the paid plan, a monthly spend limit per project pauses the project when reached.
- Home Region **us-east-2** for everything regional; a `us_east_1` provider alias only for what
  CloudFront requires there.
- What the SCPs deny is recorded, never worked around: Access Analyzer is left out, and the GitHub
  OIDC provider (ADR-0010) cannot exist here. Until Phase 11 decides otherwise, deployments run
  from the owner's machine with a 12-hour `aws login` session, and no access key exists anywhere.

**Three Terraform stacks** (ADR-0014): `bootstrap` (state bucket, its key, the budget; local state),
`account` (guardrails, CloudTrail, alarms, the platform key, the local Bedrock role) and
`environments/dev`. `scripts/tf.sh` refuses another account and the root user, and applies only a
saved plan.

**The domain is a free `is-a.dev` subdomain:** `sentineledge.is-a.dev`, with the platform at
`app.sentineledge.is-a.dev`.
- Records are added by pull request to `is-a-dev/register` and reviewed by volunteers, so each one
  takes hours to days. The design keeps their number at three, all published before any deploy
  window: the parent (CAA only: `issue amazon.com`, `issuewild ";"`), one ACM validation CNAME,
  and, in Phase 5, the CloudFront CNAME.
- One exact-name certificate for `app.sentineledge.is-a.dev` in each of us-east-1 (CloudFront) and
  us-east-2 (the internal ALB). ACM gives the same validation record to every certificate this
  account requests for the name, so the record is published once and survives every teardown.
  Certificates are free and stay between windows.
- CloudFront forwards the viewer's Host header to the origin, so the CloudFront → ALB hop is
  verified against the same name (ADR-0001's HTTPS origin, with no second certificate name).
- The CloudFront distribution is kept between windows (free when idle), so its CNAME does not
  change and needs no new pull request.

**NAT is a switch:** `nat_mode` is `none` between windows (no egress, nothing hourly), `instance`
in a window (one t4g.nano NAT instance, about a tenth of a NAT gateway's cost) or `gateway`. The
instance has no SSH, key pair or IAM role, requires IMDSv2, and admits only HTTP and HTTPS from the
app subnets.

**One deploy window for Phases 4 and 5**, about three days, then everything hourly is destroyed.
The standing cost between windows is the two KMS keys, about $2 a month.

## Security impact
- Mitigates T-IAC-01..04, T-AWS-01..03 and T-COST-01; partly T-DB-01 (network and groups now, the
  database in Phase 4); prepares T-DNS-01 (CAA records generated, published in Phase 5).
- Controls C-IAC-01..04, C-NET-01, C-NET-02, C-NET-04, C-AWS-01, C-LOG-04, C-MON-02, C-COST-01,
  C-IAM-01, C-IAM-03, and C-AI-07 extended.
- New residual risks, accepted: SCPs that cannot be read; no keyless CI route into the account;
  a parent DNS zone run by volunteers; one NAT for both zones in dev.

## Alternatives considered
- **Activate advanced features.** Rejected: irreversible, and it trades a hard spend cap for
  budget alerts.
- **A new account through the standard ("advanced") sign-up.** Not needed: everything Phases 3 to 5
  require works here, as tested.
- **No custom domain (`*.cloudfront.net`).** Rejected: no ACM or CAA evidence, and an HTTP hop to
  the origin.
- **A paid domain.** Cleanest, and a few dollars a year, but the owner asked for a free option;
  switching later changes one variable and three records.
- **Interface VPC endpoints instead of NAT.** Rejected for cost: seven endpoints in two zones cost
  more per hour than a NAT gateway.

## Consequences
- Phase 4 adds the workload into `environments/dev` and needs `nat_mode = "instance"` only during
  the window.
- Phase 5 needs the validation record published (certificates `ISSUED`) before CloudFront is
  created.
- Phase 11 must revisit ADR-0010.
- If the account ever moves to advanced features, Access Analyzer can be added to the account stack.
