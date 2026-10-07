# Secure development lifecycle

Security is part of every phase's definition of done, not a later phase. A phase is complete only
when every item below that applies to it is true.

## Definition of done (every phase)

1. **Threat model updated** for any new boundary, data flow, asset, or role (`threat-model.md`).
2. **Controls recorded** in `security-controls.md` with implementation and evidence.
3. **Capability register updated** with correct provenance; guard tests adjusted deliberately.
4. **Negative tests** exist for each new control (the attack fails), not only positive tests.
5. **Gates pass:** Gitleaks, Ruff, Bandit, mypy strict, pip-audit, npm audit, ESLint, tests,
   coverage ≥ 90%. Later phases add Semgrep, Checkov, Trivy, SBOM, ZAP.
6. **No secrets** in code, images, Terraform, or workflow files.
7. **ADR** written for any decision with security trade-offs.
8. **Docs** for the phase's area written or updated; README status table updated.
9. **Real vs simulated** wording checked in UI and docs.
10. **Runbook** added or updated for any new operational failure mode.

## Security focus by phase

| Phase | Security deliverables beyond features |
|---|---|
| 1 | Threat model baseline, control matrix, headers, secure errors, logging, provenance register, CI gates |
| 2 | Auth/RBAC negative tests (bypass, escalation, enumeration), audit hash chain, DB role separation |
| 3 | Checkov clean on all modules, IAM permission documentation, state security, account guards |
| 4 | Private-only verification, Secrets Manager wiring, CloudWatch alarms, destroy instructions |
| 5 | WAF rule tests against own domain, origin-bypass verification, TLS validation, cert alerting |
| 6 | OWASP API Top 10 mapping per endpoint, authorization matrix test over the route table |
| 7 | Detection logic tests, incident evidence integrity, simulator labelling |
| 8 | All scanners gating, SBOM per build, vulnerability SLAs |
| 9 | Prompt-injection corpus, output schema enforcement, approval workflow tests |
| 10 | STRIDE/PASTA in-app, exception expiry enforcement, change records |
| 11 | OIDC, environment protection, post-deploy validation, DAST |
| 12 | Full review, final assessment, demo scenarios, lessons learned |

## Severity gates (from Phase 8)

Critical and high findings fail the pipeline by default. Exceptions require a risk-acceptance
record (requester, justification, compensating control, approver, expiry), which Phase 10 models.
