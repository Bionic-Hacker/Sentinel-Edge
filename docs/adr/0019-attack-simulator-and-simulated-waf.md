# ADR-0019: Attack simulator and simulated WAF

- **Status:** Accepted
- **Date:** 2026-10-07
- **Phase:** 7
- **Builds on:** ADR-0008 (WAF changes via Terraform), ADR-0009 (provenance), ADR-0016 (local-first
  phase order), ADR-0018 (event pipeline and incidents)

## Context
Phase 7 builds the security operations side of SentinelEdge before any AWS resource exists
(ADR-0016). Real attack traffic is rare on a local stack, and the AWS WAF it will sit behind
arrives in Phase 5. To show the detection pipeline, the incident workflow and the dashboard
doing real work, the platform needs attack activity it can generate on demand, and a way to
show what a WAF in front of it would block or let through.

That creates obvious risks. An "attack generator" can become an attack tool, simulated data
can be mistaken for real, and a dashboard switch that changes WAF behaviour contradicts the
rule that real WAF changes go only through reviewed Terraform (ADR-0008).

## Decision

**Safe by construction, not by policy.**
- **No network traffic.** A scenario builds synthetic request records in memory and passes them
  to the same functions that analyse real requests. Nothing is sent to any host, including
  SentinelEdge's own API.
- **No target.** `POST /api/v1/simulator/runs` accepts a scenario name and nothing else: no URL,
  host, address or payload. There is no parameter to point it anywhere.
- **Reserved values only.** Attacker and user addresses come from the IETF documentation ranges
  (RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24); account names use the reserved
  `.example` domain (RFC 2606); advisories are synthetic (`SIM-YYYY-NNNN`). No simulated value
  belongs to a real person or network.
- **Labelled.** Every event, detection and incident a run produces is `SIMULATED` (ADR-0009).
  Correlation never mixes provenance (ADR-0018), so a simulation cannot raise or join a real
  incident, and the dashboard shows simulated data only in its simulated view, under a banner.
- **Controlled.** Only leads (ADMIN, SECURITY_ENGINEER) can run scenarios or change the simulated
  WAF; analysts can review runs. Runs use the `expensive` rate limit (6 per minute), are
  deterministic for a seed, and every run and every WAF change is audited (`simulator.run`,
  `simulator.waf_rule_changed`).

**Eleven scenarios**, each demonstrating a part of the platform: SQL injection, cross-site
scripting, path traversal, command injection, SSRF, credential stuffing (one sign-in succeeds,
so COR-007 fires), bot and scanner activity, API abuse (rate-limit trips plus BOLA enumeration),
suspicious authentication (MFA failures, then refresh-token replay), certificate expiration and
a vulnerable dependency. Activity is spread over the five minutes before the run, so the
dashboard's hourly series looks like traffic rather than a single spike.

**A simulated WAF with AWS semantics.** The pipeline for each synthetic request is: the real
HTTP analysis rules → the simulated WAF → (if not blocked) the application's own analysis and
the real correlation engine. Each of the 17 HTTP rules has a mode in the simulated web ACL
(`sentineledge-simulated-acl`):

| Mode | Behaviour (as AWS WAF) |
|---|---|
| `block` (default) | The first matching rule in block mode ends the request: a WAF event with outcome `blocked`; nothing reaches the application |
| `count` | The match is logged as a WAF event with outcome `detected` and evaluation continues; the request reaches the application, whose own analysis records it too |
| `off` | The rule is not evaluated |

Switching the SQL injection rules from block to count and re-running the scenario shows defense
in depth: the same payloads now reach the application and are detected there. COR-003 also
changes: it is lowered one level when every request was blocked at the edge, and keeps (or, if
a payload was served, raises) its severity when they got through. Each rule shows a
comparable AWS managed rule group (for example `AWSManagedRulesSQLiRuleSet`) for orientation;
the simulated WAF runs SentinelEdge's own rules, not AWS's.

**Separate from the real WAF.** This is the only place in SentinelEdge where a WAF rule can be
switched from the dashboard, and it changes simulated state only. The page says so, the
capability register classifies it as `SIMULATED` (`sim.waf_toggle`), and real AWS WAF rules still
change only through Terraform pull requests with review (ADR-0008, Phase 5). The application
never receives write permissions on AWS WAF.

## Security impact
Mitigates T-SO-08 (simulator abused against another system) and, with ADR-0018, T-SO-02
(simulated data mixed with real). Supports T-WAF-01 and T-WAF-02 by keeping dashboard WAF
controls out of the real change path.

## Alternatives considered
- **Replaying attack traffic over HTTP against the local stack:** more realistic, but a tool
  that sends attack payloads to a configurable host is an attack tool, and the traffic would be
  indistinguishable from real activity in the live view.
- **Seeded fixture data:** safe and simple, but static. It would not exercise the real rules,
  the WAF modes or correlation, so it proves nothing about the pipeline.
- **Running AWS WAF early:** real, but contradicts the local-first cost plan (ADR-0016) and
  cannot be exercised safely without sending attack traffic at an AWS endpoint.

## Consequences
Simulated records accumulate in the same tables as live ones, distinguished by provenance; the
retention policy in Phase 12 covers both. When AWS WAF arrives (Phase 5), its logs become a new
`REAL_AWS` event source shown in the live view, while the simulated WAF remains for
demonstrations and training.
