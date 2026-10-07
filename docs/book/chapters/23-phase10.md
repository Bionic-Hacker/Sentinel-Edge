# Phase 10 — Threat Modeling and Governance

<p class="lead">The threat model and control matrix have so far lived in Markdown. Phase 10 brings them into the application, alongside exceptions, risk acceptance and change management. <span class="status plan">Planned</span></p>

## Scope

- **Threat modeling module.** STRIDE and PASTA, with assets, trust boundaries, data flows, threats, attack paths, controls and residual risk. The first model in the module is SentinelEdge's own, migrated from `docs/threat-model.md` rather than retyped.
- **Control catalogue and mappings.** Controls linked to threats, requirements and evidence, so the requirement → threat → control → implementation → evidence matrix is queryable.
- **Exceptions and risk acceptance.** Every exception names a requester, business justification, risk, compensating control, approver and expiry. Expiry is enforced, never left to lapse. EXC-0001 and EXC-0002 migrate in from `docs/governance/exceptions.md`.
- **Change management.** Security-sensitive changes produce a change ID, requester, description, risk, approval, implementation, validation and rollback plan. WAF change requests (ADR-0008) are the first consumer.
- **Security posture score.** Scored by category (network, WAF, API, identity, vulnerability management, TLS, logging, monitoring, AI, DevSecOps, governance). The score must be **explainable**: each number links to the controls and evidence behind it, never an arbitrary or AI-generated figure.

:::planned Separation of duties
A requester cannot approve their own exception or change. On a single-maintainer project this is enforced by role checks and recorded in the audit log, and that limitation is stated openly.
:::
