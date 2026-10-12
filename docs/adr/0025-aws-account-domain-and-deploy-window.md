# ADR-0025: The AWS account, the domain and the deploy window, as built

- **Status:** Accepted; domain settled 2026-10-12 (`sentineledge.bionichacker.dev`, see below)
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

**The domain: `sentineledge.bionichacker.dev`, a Route 53 zone delegated from the owner's domain.**
- **What was tried.** The owner first asked for a free name. `sentineledge.is-a.dev` was chosen on
  2026-10-09, but on 2026-10-10 is-a.dev had disabled pull requests "until further notice". The
  fallback, a free `sentineledge.dedyn.io` zone at deSEC, was closed the same night: deSEC had
  suspended new `dedyn.io` names after abusive bulk registrations. On 2026-10-12 FreeDNS
  (afraid.org) was tested: its shared domains refuse CNAME records and any name starting with `_`,
  so neither CloudFront's record nor ACM's validation record could be published.
- **The decision (2026-10-12).** The owner registered `bionichacker.dev` at Porkbun as a general
  domain for this and later projects. Its DNS stays at Porkbun. The platform is served at the apex
  of `sentineledge.bionichacker.dev`, a name delegated by four NS records to a Route 53 zone that
  `environments/dev` owns ($0.50 a month). Each project gets its own name, and tearing one down
  removes only its zone.
- **In the zone, as code:**
  - CAA at the apex: `0 issue "amazon.com"`, `0 issuewild ";"` (and an optional `iodef`).
  - One exact-name certificate in each of us-east-1 (CloudFront) and us-east-2 (the internal ALB).
    ACM gives the same validation record to every certificate this account requests for the name,
    so the us-east-1 certificate publishes it and both wait on it. The wait (`dns_delegated`) is
    switched on once the registrar's NS records are live, so no apply waits on DNS it cannot see.
  - The zone is `prevent_destroy`: deleting it while the registrar still delegates to its name
    servers would leave a dangling delegation that anyone can claim by creating zones until
    Route 53 assigns the same servers. The teardown removes the NS records first.
  - CloudFront forwards the viewer's Host header to the origin, so the CloudFront → ALB hop is
    verified against the same name (ADR-0001's HTTPS origin, with no second certificate name).
  - The CloudFront distribution is kept between windows (free when idle), so its alias record
    does not change. `.dev` is HSTS-preloaded, so browsers never use plain HTTP for it.
- **Not done, recorded:** DNSSEC (Porkbun's DNS cannot hold the DS record a delegated name needs)
  and Route 53 query logging (deferred to Phase 5 with the CloudFront and WAF logs). Both are written in place
  as Checkov exceptions.

**NAT is a switch:** `nat_mode` is `none` between windows (no egress, nothing hourly), `instance`
in a window (one t4g.nano NAT instance, about a tenth of a NAT gateway's cost) or `gateway`. The
instance has no SSH, key pair or IAM role, requires IMDSv2, and admits only HTTP and HTTPS from the
app subnets.

**One deploy window for Phases 4 and 5**, about three days, then everything hourly is destroyed.
The standing cost between windows is the two KMS keys and the DNS zone, about $2.50 a month.

## Security impact
- Mitigates T-IAC-01..04, T-AWS-01..03 and T-COST-01; partly T-DB-01 (network and groups now, the
  database in Phase 4); mitigates T-DNS-01 (CAA, exact-name certificates, a zone that cannot be left dangling).
- Controls C-IAC-01..04, C-NET-01, C-NET-02, C-NET-04, C-AWS-01, C-LOG-04, C-MON-02, C-COST-01,
  C-IAM-01, C-IAM-03, C-DNS-01, and C-AI-07 extended.
- New residual risks, accepted: SCPs that cannot be read; no keyless CI route into the account;
  no DNSSEC on the platform's zone; one NAT for both zones in dev.

## Alternatives considered
- **Activate advanced features.** Rejected: irreversible, and it trades a hard spend cap for
  budget alerts.
- **A new account through the standard ("advanced") sign-up.** Not needed: everything Phases 3 to 5
  require works here, as tested.
- **No custom domain (`*.cloudfront.net`).** Rejected: no ACM or CAA evidence, and an HTTP hop to
  the origin.
- **is-a.dev**, **deSEC's dedyn.io** and **FreeDNS** (free subdomains). The first two suspended new
  names on 2026-10-10; FreeDNS refuses the CNAME and underscore records ACM and CloudFront need.
- **The whole domain in Route 53.** Simpler delegation, but SentinelEdge's Terraform would then
  own a domain meant for other projects too.
- **DNS at deSEC (free) for the delegated name.** Saves $0.50 a month, but Terraform could not
  publish the records or wait for the certificates without a third provider and its token.
- **The cheapest extensions (.vip, .xyz).** A few dollars cheaper, but often flagged by corporate
  web filters, which matters for a portfolio.
- **Interface VPC endpoints instead of NAT.** Rejected for cost: seven endpoints in two zones cost
  more per hour than a NAT gateway.

## Consequences
- Phase 4 adds the workload into `environments/dev` and needs `nat_mode = "instance"` only during
  the window.
- Before Phase 5: add the delegation at Porkbun and set `dns_delegated = true`; Phase 5 builds
  CloudFront on the issued certificate ARN and adds the alias records to the zone.
- Phase 11 must revisit ADR-0010.
- If the account ever moves to advanced features, Access Analyzer can be added to the account stack.
