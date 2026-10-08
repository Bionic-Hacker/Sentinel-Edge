# ADR-0020: Application security scanning and the scan gate

- **Status:** Accepted
- **Date:** 2026-10-08
- **Phase:** 8
- **Builds on:** ADR-0010 (CI pinning), ADR-0011 (security headers), ADR-0013 (security gates from
  Phase 1), ADR-0016 (local-first phase order)

## Context
Since Phase 1, CI has run Gitleaks, Bandit, pip-audit and npm audit (ADR-0013). Phase 8 adds the
rest of the spec's scanning (§19): SAST beyond Bandit, container and IaC scanning, SBOMs and
DAST. Many scanners produce many findings, and most are not equally urgent. A gate that blocks on
everything gets switched off; a gate that blocks on nothing is decoration. The gate also has to
work the same on a laptop and in CI, and it must never pass because a scanner quietly failed.

## Decision

**One pipeline, two places.** `scripts/scan.sh` runs every scanner and the gate; `make scan`
runs it locally and the `security-scans` CI job runs it on every push. Each scanner writes JSON
to `reports/scan/`.

| Category | Tool | Scope |
|---|---|---|
| SAST | Semgrep (registry rulesets + SentinelEdge rules), Bandit | Backend and SPA source |
| SCA | Trivy `fs` | Python and npm lock files |
| Secrets | Gitleaks | Working tree and full history |
| IaC | Checkov | Dockerfiles, GitHub Actions, Terraform |
| Container | Trivy `image` | API and web images, from `docker save` tarballs |
| SBOM | Syft (CycloneDX) | API image, web image, source tree |
| DAST | ZAP baseline + ZAP API scan (authenticated) | The local stack only |

**SentinelEdge's own Semgrep rules** encode this project's rules as code, each with annotated
tests run in CI (`make scan-test`): SQL never built from strings; outbound HTTP only through the
egress guard; no unsafe deserialisation; JWTs always verified; no shell commands; no secrets in
logs; in the SPA, network calls only through the API client, no web storage, no raw HTML, no
dynamic code, no inline styles, no navigation to computed URLs.

**The gate** (`python -m app.scanning.gate`) normalises every report into one de-duplicated list
of findings (tool, category, rule, severity, component, location, fingerprint, fix) and decides:
- A **critical or high** finding blocks, unless an unexpired accepted risk covers it.
- A critical or high **package vulnerability with no fixed version published** cannot be fixed by
  changing this repository. It is reported on every run as *awaiting an upstream fix* and does
  not block; it blocks on the first run after a fix is published.
- **Medium, low and info** are reported, never blocking.
- **Fail closed:** no reports, an unreadable report, a malformed accepted-risk register, or any
  expected report missing (`--expect`) exits 2. A scanner that crashed cannot let the build pass
  on the reports the others wrote.
- Severity mapping: scanner severities as given; Checkov failures without a severity count as
  high; ZAP risk 3/2/1/0 is high/medium/low/info; every Gitleaks finding is critical.

**Accepted risks** live in `scanning/accepted-findings.toml`, reviewed like code: each entry names
the finding (fingerprint, or tool and rule with an optional component pattern), the
justification, the compensating control, the approver and an expiry date. After the expiry the
entry covers nothing. In-code suppressions (`# nosemgrep`, `# checkov:skip`, `# nosec`) are
allowed only with the reason written beside them.

**Scanners are contained.** Every scanner runs in an image pinned by tag and digest, as the
calling user, with the repository mounted read-only; none gets the Docker socket (images are
scanned from tarballs). Checkov runs with `skip-download` and Semgrep with metrics off. `make
image-digests` reports pins whose tag has moved, because Dependabot does not update pins outside
`FROM` lines.

**Authenticated DAST without risk to data.** The ZAP API scan reads the OpenAPI document pinned
to the local stack, with logout removed so the scan cannot end its own session. It signs in as
`dast-scanner@example.com`, a VIEWER with no usable password; the CLI issues one 60-minute
session per scan and revokes it when the scan ends, however it ends. As a viewer it reads what a
viewer may and every write it attempts is refused, so active payloads cannot change data. The
token reaches ZAP through a mode-600 env file, never a command line.

**Images get OS fixes at build time.** Both runtime images run `apk upgrade` / `apt-get upgrade`
on top of the pinned base, so a fix published after the base image was built reaches the next
build without waiting for the base to be rebuilt. The API base moved from Debian 12 (oldstable)
to Debian 13 after the first scan.

## Consequences
- The first full scan, in M1, blocked on nothing once the scanners themselves were fixed. After
  the move to Debian 13, 44 high OS package vulnerabilities in the API base have no fix yet and
  are reported on every run.
- The gate works as designed when an upstream fix appears: the first import after M2 blocked on
  CVE-2026-4775 (tiff, web image) the day Alpine published 4.7.2-r0; the build-time upgrade fixed
  it and the next import marked it fixed.
- The authenticated ZAP API scan reached 66 endpoints and passed every active rule (SQL
  injection on five engines, XSS, path traversal, command injection, SSRF to cloud metadata,
  template injection, Log4Shell); it raised only low and informational alerts.
- Scans take minutes, not seconds: `make scan` stays a separate target from `make check`.
- Package vulnerabilities in the base image that never get a fix stay visible indefinitely. The
  remedy is a smaller base (distroless or Alpine for the API), planned with Phase 12 hardening.
