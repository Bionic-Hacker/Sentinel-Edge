# Security exceptions

Spec §38 requires every exception to name a requester, business justification, risk,
compensating control, approver, and expiry. Since Phase 10 (v0.6.0) **the application is the
system of record**: exceptions are requested, decided and closed on SentinelEdge's
**Compliance > Exceptions** page (`/api/v1/exceptions`), with their history read from the
hash-chained audit log ([ADR-0023](../adr/0023-exceptions-change-management-separation-of-duties.md)).
This file no longer holds entries, and is kept for the rules and the links.

## Rules (enforced by the application)

- **Whoever asks cannot approve.** A different lead (ADMIN or SECURITY_ENGINEER) decides. The
  service refuses self-approval, and so does a database CHECK.
- **Every exception names what still protects the system** (the compensating control) and its
  exit criteria.
- **Every exception expires**, no later than its risk allows: critical 30 days, high 90, medium
  180, low 365. On its date it expires automatically. To keep it, request a new exception with a
  fresh review; a decided exception is never edited.
- **Ending early needs a reason.** Withdraw a request before the decision, or close an approved
  exception once the issue is fixed.
- **Configuration that implements an exception carries its ID** in a comment (for example a
  Dependabot `ignore` rule), so the link can be audited in both directions.
- **Scan-finding exceptions feed the scan gate.** After a decision, run `make accepted-risks`
  (stack running) and commit `scanning/accepted-findings.toml`; the file is generated, never
  edited by hand.

How to handle an expiring exception, a failed change or a workflow bypass:
[governance runbook](../runbooks/governance.md).

## Migrated entries

Migration 0011 imported the two exceptions this register held, with their original fields, as
records marked as imported (the requester and approver kept as written then). Look them up in
the application.

| ID | Subject | Approved | Expires |
|---|---|---|---|
| EXC-0001 | ESLint held on major version 9 (`eslint-plugin-jsx-a11y` peer range) | 2026-10-07 | 2027-01-07 |
| EXC-0002 | TypeScript held below major version 7 (`typescript-eslint` support) | 2026-10-07 | 2027-01-07 |

`.github/dependabot.yml` still carries `EXC-0001` and `EXC-0002` beside the `ignore` rules that
implement them.
