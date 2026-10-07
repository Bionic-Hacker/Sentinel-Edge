# Phase 8 — Application Security Scanning

<p class="lead">Phase 1 shipped baseline gates. Phase 8 completes the scanner set, generates an SBOM on every build, and turns findings into a managed vulnerability lifecycle with SLAs. <span class="status plan">Planned</span></p>

## Scope

| Category | Tool | Adds to Phase 1 baseline |
|---|---|---|
| SAST | Semgrep (+ Bandit, Ruff S) | Cross-language rules, custom rules for project patterns |
| SCA | pip-audit, npm audit | Results ingested as findings, not just gates |
| Secrets | Gitleaks | Unchanged; findings recorded |
| Container | Trivy | Image OS and library CVEs; misconfiguration checks |
| IaC | Checkov | Every Terraform module scanned before Phase 3 applies anything |
| DAST | OWASP ZAP | Authenticated scans against the local stack; fills "Last scan" in the API Security Center |
| SBOM | Syft | CycloneDX per build: dependencies, versions, licenses, known vulnerabilities |

## Vulnerability management

Each finding records an ID, source, severity, CVSS, affected component, detection date, status, owner, remediation recommendation, due date and evidence. Statuses are Open, Triaged, In Progress, Remediated, Accepted Risk and False Positive. Severity drives a due date. **Critical and high findings fail the pipeline by default.** The only way past the gate is a risk-acceptance record with requester, justification, compensating control, approver and expiry, which Phase 10 models in the application.

:::planned Design notes
- Scanners must be configured and producing results, not merely listed (spec §19).
- SBOM status appears on the dashboard. A vulnerable dependency becomes both a finding and, through the simulator path, a demonstrable event.
:::
