# ADR-0008: WAF changes through Terraform, not the dashboard

- **Status:** Accepted
- **Date:** 2026-10-06
- **Phase:** 5, 7, 10

## Context
Spec §13 asks for a WAF management interface but forbids presenting simulated changes as real.
A dashboard holding `wafv2:Update*` permissions would be a high-value target and would make
Terraform state drift from reality.

## Decision
- The dashboard **reads** real WAF state (`GetWebACL`, `GetSampledRequests`, logs) with a
  read-only role. That data is labelled REAL_AWS.
- A requested change (enable a rule, add an exception) creates a **change request** (spec §39).
  Once approved, it is applied by updating Terraform variables through a pull request; CI runs
  `plan`, a human approves, and the pipeline applies.
- In-dashboard rule toggling exists only in the simulator and is labelled SIMULATED.

## Security impact
The internet-facing application holds no permission to weaken the WAF (T-WAF-02). Every real
change has an approver, a plan, and a rollback (revert the PR). Controls C-WAF-04, C-GOV-03.

## Consequences
Real changes take minutes, not seconds. That is the point, and it is how mature teams operate.
