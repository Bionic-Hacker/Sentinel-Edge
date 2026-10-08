# Application security scanning

Phase 8 adds one scan pipeline that runs the same way on a laptop (`make scan`) and in CI (the
`security-scans` job). Policy: ADR-0020.

| Category  | Tool                  | Scans                                                  | Report                          |
|-----------|-----------------------|--------------------------------------------------------|---------------------------------|
| SAST      | Semgrep               | Python and TypeScript: registry rulesets + `semgrep/`  | `semgrep.json`                  |
| SAST      | Bandit                | `backend/app`                                          | `bandit.json`                   |
| SCA       | Trivy (`fs`)          | `requirements*.txt`, `package-lock.json`               | `trivy-fs.json`                 |
| Secrets   | Gitleaks              | working tree and full git history (`.gitleaks.toml`)   | `gitleaks.json`                 |
| IaC       | Checkov               | Dockerfiles, GitHub Actions, Terraform (`checkov.yaml`) | `checkov.json`                  |
| Container | Trivy (`image`)       | API and web images, from `docker save` tarballs        | `trivy-image-{api,web}.json`    |
| SBOM      | Syft                  | API image, web image, source tree (CycloneDX)          | `sbom-{api,web,source}.cdx.json`|
| DAST      | ZAP baseline (passive)| the local stack at `http://localhost:8080` only        | `zap-baseline.json`             |

All reports land in `reports/scan/` (git-ignored; uploaded as a CI artifact for 30 days).

## Running

```
make scan        # everything except DAST, then the gate
make dev         # DAST needs the stack
make dast        # ZAP baseline, then the gate over every report
make scan-gate   # re-apply the gate after editing accepted-findings.toml
make sbom        # SBOMs only
make scan-test   # test the SentinelEdge Semgrep rules
make scan-import # store reports/scan in vulnerability management (the stack must be running)
```

`make scan-import FROM=<dir> SOURCE=ci COMMIT=<sha>` imports a downloaded CI artifact instead
(`gh run download <run-id> -n security-scans-<run-id> -D <dir>`).

Single steps: `scripts/scan.sh sast`, `sca`, `secrets`, `iac`, `container`, `sbom`, `dast`, `gate`.
`SEMGREP_RULESETS=""` skips the registry rulesets when offline; CI always uses them.

## The gate

`python -m app.scanning.gate` parses every report into one normalised finding list, de-duplicated
by fingerprint, and writes it to `reports/scan/findings.json`. Then:

* **Critical or high** findings fail the build, unless an unexpired accepted risk covers them.
* A critical or high **package vulnerability with no fixed version** is listed as *awaiting an
  upstream fix* on every run and does not block; it blocks as soon as a fix is published.
* **Medium, low and info** are reported, never blocking.
* No reports, an unreadable report or a malformed `accepted-findings.toml` exit 2: a scan that
  failed silently never passes.

Severity mapping: scanner severities are used as given; Checkov failures without a severity
count as high; ZAP risk 3/2/1/0 is high/medium/low/info; every Gitleaks finding is critical.

## Vulnerability management

`make scan-import` sends the gate's `findings.json` and the SBOMs to the API container's CLI
(`python -m app.cli import-scan`, over stdin). Findings are de-duplicated per application by
fingerprint; one that a scan no longer reports is marked fixed, but only if that scan included
every report able to produce it, so a scan without DAST never fixes a ZAP finding. New and
reopened critical or high findings become security events. Remediation SLA from detection:
critical 7 days, high 30, medium 90, low 180. Risk acceptance (leads only) needs a
justification, a compensating control and an expiry within the severity's limit (critical 30
days, high 90, others 365); an expired acceptance reopens its finding.

## SentinelEdge Semgrep rules

`semgrep/python.yml` and `semgrep/frontend.yml` encode this project's own rules: SQL never built
from strings, outbound HTTP only through the egress guard, no unsafe deserialisation, JWTs always
verified, no shell commands, no secrets in logs; in the SPA, network calls only through the API
client, no web storage, no raw HTML, no dynamic code, no inline styles (CSP), and no navigation to
computed URLs. Each rule has annotated examples (`python.py`, `frontend.tsx`) that CI tests.

## Accepted risks

`accepted-findings.toml` is the register. Each entry names the finding (fingerprint, or tool and
rule with an optional component pattern), the justification, the compensating control, the
approver and an expiry date. Prefer fixing. Suppressions in code (`# nosemgrep: <rule>`,
`# checkov:skip=<id>: <reason>`, `# nosec`) are allowed only with the reason written beside them.

## Safety

Every scanner runs in an image pinned by tag and digest (`make image-digests` reports pins whose
tag has moved; `UPDATE=1` rewrites them) as the calling user with the repository mounted
read-only, and none is given the Docker socket. Checkov runs with `skip-download`, Semgrep with
metrics off. ZAP runs the passive baseline only, and only against the local stack.
