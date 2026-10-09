# ADR-0023: Security exceptions, change management and separation of duties

- **Status:** Accepted
- **Date:** 2026-10-08
- **Phase:** 10
- **Builds on:** ADR-0005 (audit log), ADR-0008 (WAF changes via Terraform), ADR-0015 (database
  roles), ADR-0019 (simulated WAF), ADR-0020 (scan gate), ADR-0021 (risk acceptance)

## Context
Two decisions carry most of a security programme's risk: living with a weakness for a while (an
exception), and changing something that protects the system (a change). Until Phase 10 the
exceptions lived in `docs/governance/exceptions.md`. The scan gate read its own accepted-risk
file, and nothing recorded change approvals at all. The spec asks for a requester, a
justification, a compensating control, an approver and an expiry for every exception (§38). It
asks for an approver other than the requester, a rollback plan and validation for every
security-sensitive change (§39).

## Decision

**Whoever asks cannot approve.** This applies to exceptions and change requests alike. The
service refuses self-approval with 409 `separation_of_duties`. The response tells the UI why,
so it can say so rather than hide the button. A database CHECK (`approver_id <> requester_id`)
refuses it again, so a bug in the service cannot approve anything. On this single-maintainer
project that means a second lead account, which is deliberate.

**Exceptions (EXC-n).**
* **Requesting:** leads, or DEVELOPERs for applications they own.
* **Contents:** scope (dependency, scan finding, control, configuration, other), risk level,
  justification, compensating control, exit criteria and an expiry.
* **Expiry limit:** no later than the risk level allows: critical 30 days, high 90, medium 180,
  low 365.
* **Deciding:** a different lead approves or rejects, with a reason for a rejection.
* **Ending:** the requester may withdraw before the decision. An approved exception expires on
  its date, or a lead or the requester closes it early with a reason once the issue is fixed.
  The expiry sweep runs on every read and write, so expiry never depends on a scheduler.
* **Migration:** migration 0011 imports EXC-0001 and EXC-0002 from the register, so they are
  migrated rather than retyped.

**The application is the system of record for the scan gate.** Approved `scan_finding`
exceptions are exported by `make accepted-risks` to `scanning/accepted-findings.toml`, which the
gate reads (ADR-0020). The file now says at the top that it is generated. An expired exception
stops covering its finding at the next export.

**Change requests (CHG-n).**
* **Submitting:** leads, or DEVELOPERs for applications they own. A request carries the type,
  risk level, description, a rollback plan and a validation plan.
* **Moves:** submitted → approved or rejected (by a different lead), or cancelled → implemented
  (with a reference such as a pull request) → validated or rolled back.
* **Who moves it:** rejection, cancellation, validation and rollback need a reason. Validation is
  lead-only; the requester or a lead implements and may roll back.
* **WAF changes:** a `waf_rule` change targets a rule of the simulated WAF and is allowed only on
  SentinelEdge itself. Implementing it switches the rule's mode, and rolling it back restores the
  previous mode, both through the same function the simulator uses. Real WAF rules still change
  only through reviewed Terraform with read-only application access (ADR-0008).

**Decisions are final.** Triggers refuse a rewritten decision and the revival of a rejected,
withdrawn or cancelled record. The application role holds no DELETE on either table. A record's
history is read from the hash-chained audit log, where each step is written in the same
transaction as the step itself, so the history and the record cannot disagree.

**Access.** Every role reads; DEVELOPERs see only their own applications (404, audited). The API
returns `permissions` and `available_moves`; the UI renders them and never re-derives the rules.

## Alternatives considered
- **Keep the Markdown register.** Rejected: it cannot enforce an approver other than the
  requester, or an expiry.
- **Enforce separation of duties in the service only.** Rejected: the CHECK costs one line and
  catches a bug that would otherwise approve silently.
- **A scheduler for expiry.** Rejected for now: a sweep on every read and write gives the same
  answer with no extra moving part. A scheduled worker arrives with the AWS phases.

## Incidents during the phase (kept as lessons)
1. **Tests depended on reference numbers.** The two seeded exceptions shifted every new
   reference, and tests that assumed EXC-0001 failed. Tests now use the references the API
   returns, and today's date from the clock.
2. **Validation refused the screenshot seed.** A rollback plan shorter than 20 characters was
   rejected by the API. The seed was wrong, not the rule.

## Consequences
- `docs/governance/exceptions.md` now points to the application. The two exceptions it held live
  in the Compliance page with their full history.
- Running `make accepted-risks` after a scan-finding decision, and committing the file, is part
  of the [governance runbook](../runbooks/governance.md).
- Phase 5 adds the real WAF. Its rule changes will be Terraform pull requests referenced from
  change requests, not changes made by the application.
