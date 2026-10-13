# ADR-0029: The edge read back: real WAF blocks and ACM certificates in the dashboard

- **Status:** Accepted
- **Date:** 2026-10-13
- **Phase:** 5
- **Decided by:** Bionic-Hacker (project owner)
- **Builds on:** ADR-0008 (WAF only through Terraform), ADR-0009 (provenance), ADR-0018
  (correlation), ADR-0026 (the API's task role), ADR-0027 (the edge)

## Context
Phase 5 planned two dashboard capabilities alongside the edge itself: **WAF log ingestion** (real
AWS WAF blocks on the Threats page, next to labelled simulated ones) and **ACM certificate
monitoring** (inventory, expiry, renewal, with alerting). The first deploy window built and
verified the edge, but these two were not yet built: the WAF and Certificates pages still read
"Planned", and the page banner claimed no AWS resources were connected. The owner chose to build
them while the window was open and prove them against the real account.

## Decision

**WAF blocks become real security events.** The API reads new `BLOCK` records from the WAF log
group in us-east-1 (`logs:FilterLogEvents`) and stores each as a security event: provenance
`REAL_AWS`, source `waf`, outcome `blocked`, category and severity from the terminating rule
(managed sub-rules refine it: an SQLi rule is `sql_injection`, Log4j is `command_injection`, the
IP reputation list is `bot`). They go through correlation like any other event, so five blocked
injections from one address raise COR-003, one level lower because nothing reached the app.
Reading starts from the newest stored block minus five minutes (late delivery), at most a day
back, at most 1,000 records a sync.

**Certificates are read live and checked.** The Certificates page lists ACM certificates in both
Regions (the edge certificate in us-east-1, the origin certificate in the home Region), cached
five minutes. Every sync checks them: 30 days before expiry (high at 14), a failed renewal, or an
expired, revoked or failed certificate raises a `certificate` event, once per certificate,
condition and day. ACM renews DNS-validated certificates on its own; the check catches the case
where it cannot.

**Once, however often it is read.** Events read from outside carry `evidence.dedupe_key` (the
CloudWatch event ID, or certificate, condition and day). A partial unique index (migration 0016)
stores each once, whatever overlaps between syncs or tasks; a duplicate is skipped inside a
savepoint.

**When.** A timer in the API (every `aws_sync_interval_seconds`, 5 minutes) runs only when either
feed is configured, which is only in AWS. Leads can also press **Sync now** (audited as
`edge.synced`). A failure in one feed does not stop the other, and is reported by exception class
only, never AWS's message.

**Least privilege.** The API's task role gains read-only access: `logs:FilterLogEvents` on the
one WAF log group, `acm:ListCertificates` (no resource-level permission exists) and
`acm:DescribeCertificate` on certificates in the two Regions. It still has no WAF permission at
all (ADR-0008): rules change only through Terraform.

**Honest labels.** WAF and certificate events are badged Real AWS. The page banner now asks the
API where it runs (`/platform/environment`, signed-in users only) instead of always saying
"local".

## Security impact
- Controls C-EDGE-05 (WAF ingestion) and C-EDGE-06 (certificate monitoring).
- T-EDGE-09: attacker-written log content is stored bounded and rendered as text only.
- T-EDGE-10: certificate expiry or failed renewal no longer goes unnoticed.
- T-EDGE-11: the new AWS access is read-only and scoped.
- Accepted: blocks are up to five minutes late on the dashboard; 1,000 records a sync bound a
  flood (the rest arrive on the next sync, within the day's lookback).

## Alternatives considered
- **Subscription filter to a Lambda.** Real time, but a second compute path, its own role and
  deployment, for a dashboard that is fine five minutes late.
- **CloudWatch alarms on ACM's `DaysToExpiry` metric.** Alarms must live in the certificate's
  Region and notify a topic there; the edge certificate is in us-east-1, the alerts topic in the
  home Region. Events in SentinelEdge reach the same incident workflow as everything else.
- **Reading WAF's sampled requests (`wafv2:GetSampledRequests`).** A WAF permission for the app,
  which ADR-0008 rules out, and only a sample.
