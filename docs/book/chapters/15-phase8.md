# Phase 8 — Application Security Scanning

<p class="lead">Phase 1 shipped a baseline of security gates. Phase 8 completes the scanner set (SAST, dependency, secret, infrastructure-as-code and container scanning, SBOMs and authenticated DAST), puts one gate in front of every build, and turns what the scanners find into a managed vulnerability lifecycle with deadlines, risk decisions and an audit trail. Released as v0.5.0.</p>

## Milestones

| Milestone | Delivered |
|---|---|
| M0 | CI on every phase-branch push; capability keys checked against the SPA's module list |
| M1 | The scan pipeline, SentinelEdge's own Semgrep rules, the scan gate and the CI `security-scans` job; every image pinned by digest |
| M2 | Vulnerability management backend: scan import, de-duplication, SLAs, risk acceptance, SBOM storage, findings as security events; OS fixes applied at image build |
| M3 | Vulnerabilities and SBOM pages, authenticated DAST, measured values on the dashboard, inventory and API Security Center |
| M4 | Cross-origin isolation, ADR-0020 and ADR-0021, remediation runbook, threat model v0.5, Edition 3 of this book, v0.5.0 |

## One pipeline, two places

{{figure:scanning|The scan pipeline. Every scanner writes JSON to one directory; the gate reads all of it and decides. The same script runs on a workstation and in CI. DAST (dashed) needs the running stack, so it runs locally.|100}}

`scripts/scan.sh` runs every scanner and then the gate. `make scan` runs it on a workstation; the `security-scans` CI job runs it on every push and keeps the reports as an artifact. `make dast` adds the ZAP scans against the running local stack.

| Category | Tool | Scope |
|---|---|---|
| SAST | Semgrep (registry rulesets + SentinelEdge rules), Bandit | Backend and SPA source |
| Dependencies | Trivy `fs` | Python and npm lock files |
| Secrets | Gitleaks | Working tree and full history |
| Infrastructure as code | Checkov | Dockerfiles, GitHub Actions, Terraform |
| Containers | Trivy `image` | API and web images, from `docker save` tarballs |
| SBOM | Syft (CycloneDX) | API image, web image, source tree |
| DAST | ZAP baseline + authenticated API scan | The local stack only |

### The project's rules, as code

Registry rulesets find generic weaknesses. They do not know this project's rules, so Phase 8 writes them down as Semgrep rules, each with annotated examples that must match (`# ruleid:`) and must not (`# ok:`), tested in CI by `make scan-test`:

- **Backend:** SQL is never built from strings; outbound HTTP goes only through the egress guard from Phase 6; no unsafe deserialisation; JWTs are always verified; no shell commands; no secrets in log calls.
- **SPA:** network calls only through the API client; no web storage (the access token lives in memory); no raw HTML, dynamic code or inline styles (the CSP forbids them anyway); no navigation to computed URLs.

A rule that is only written in a document is a hope. A rule the build checks is a control.

## The gate

`python -m app.scanning.gate` normalises every report into one de-duplicated list of findings (tool, category, rule, severity, component, location, fingerprint and fix) and decides:

- A **critical or high** finding **blocks**, unless an unexpired accepted risk covers it.
- A critical or high **package vulnerability with no fixed version published** is reported on every run as *awaiting an upstream fix* and does not block. It blocks on the first run after a fix appears.
- **Medium, low and informational** findings are reported and never block.
- The gate **fails closed**: no reports, an unreadable report, a malformed accepted-risk register, or any expected report missing (`--expect`) exits with status 2.

:::why Why an unfixable vulnerability does not block
A gate that blocks on something no change to the repository can fix teaches people to switch the gate off. The finding stays visible on every run, and it starts blocking the day the fix is published, which is exactly when there is something to do.
:::

Accepted risks live in `scanning/accepted-findings.toml`, reviewed like code. Each names the finding, the justification, the compensating control, the approver and an expiry date, after which it covers nothing. In-code suppressions (`# nosemgrep`, `# checkov:skip`, `# nosec`) are allowed only with the reason written beside them.

:::lesson A gate that passes on silence
The first version of the gate passed with three reports out of nine, because the scanners that crashed wrote nothing and "nothing found" looked like success. The gate now takes the list of reports it expects and refuses to decide without every one of them. The same review found that Syft had been failing silently: its image has no writable `/tmp`, and the quiet flag hid the error.
:::

### Contained scanners

Scanners read everything, so they are treated as untrusted software. Every scanner image is pinned by tag **and digest**, runs as the calling user with the repository mounted read-only, and never gets the Docker socket: images are exported with `docker save` and scanned as tarballs. Checkov runs without downloading anything, and Semgrep with metrics off. Dependabot updates `FROM` lines but not images referenced in scripts, so `make image-digests` reports any pin whose tag has moved, and `UPDATE=1` rewrites them for review.

### Images take OS fixes at build time

The first image scan reported 55 high OS package vulnerabilities with no fix in the API's Debian 12 base. The base moved to Debian 13, leaving 44, all awaiting upstream fixes. Both runtime images now also run `apt-get upgrade` / `apk upgrade` on top of the pinned base, so a fix published after the base image was built reaches the next build without waiting for a new base.

:::evidence The gate doing its job
The first import, after M2, blocked on CVE-2026-4775 in `tiff` in the web image: Alpine had published a fix that day, so the finding changed from *awaiting a fix* to *fixable* and the gate stopped the build. The build-time upgrade fixed it, and the next import marked it fixed automatically.
:::

## Authenticated DAST, without risk to data

An unauthenticated scan of SentinelEdge sees a sign-in page and a handful of public endpoints. To reach the API, ZAP must sign in, and an attack tool signed in to a security platform needs limits:

- It signs in as `dast-scanner@example.com`, a **VIEWER** with no usable password. As a viewer it reads what a viewer may, and every write it attempts is refused, so active attack payloads cannot change data.
- The CLI issues **one 60-minute session per scan** and revokes it when the scan ends, however it ends. The token reaches ZAP through a mode-600 file, never a command line.
- ZAP reads the OpenAPI document pinned to the local stack, with **logout removed**, so the scan cannot end its own session halfway.

:::evidence 66 endpoints, every active rule passed
On the owner's machine the authenticated API scan reached 66 endpoints and passed every active rule: SQL injection for five database engines, cross-site scripting, path traversal, command injection, SSRF to cloud metadata, template injection and Log4Shell. It raised eight low and informational alerts. One was real: the SPA lacked `Cross-Origin-Embedder-Policy`, now sent alongside COOP by both nginx and the API and checked by `make verify-hardening`. The rest describe intended behaviour, such as the SPA's fallback page for unknown paths.
:::

The API Security Center now shows each endpoint's last authenticated DAST scan, which until Phase 8 said "not connected".

## Vulnerability management

The gate decides about one build and has no memory. Vulnerability management (ADR-0021) remembers: when a finding first appeared, whether it was fixed and came back, who decided to live with it, and how long it has been open.

**Import, not upload.** `make scan-import` bundles the gate's findings and the SBOMs and pipes them into the API container's CLI over stdin. There is no upload endpoint until CI can reach a deployed API (Phase 11). Every imported string is bounded and has control characters replaced, the import is all-or-nothing, and each scan run is recorded insert-only with its commit, branch and gate result.

{{figure:vulnerability|The finding lifecycle. Nobody marks a finding fixed: only a scan that ran every report able to produce it, and no longer does, can. Dashed moves reopen a finding.|100}}

**One record per finding.** Findings are de-duplicated per application by fingerprint. A finding seen again updates its record. A finding a scan no longer reports is marked **fixed**, but only if that scan ran every report able to produce it: a scan without DAST cannot fix a ZAP finding. A fixed finding that returns is **reopened**, and its SLA clock restarts.

**Deadlines from detection:** critical 7 days, high 30, medium 90, low 180. A severity change keeps the original clock, so re-rating cannot buy time.

**The server owns the rules.** Remediators (admins, security engineers, and developers on their own applications) move findings between open and in progress. Only leads mark false positives, with a note, and a false positive stays one when the scanner reports it again. Every response carries the moves allowed for the person asking, as incidents do since Phase 7, and every change carries the record's version (stale writes get 409).

### Risk acceptance

A lead may accept a risk with a justification, a compensating control and an expiry no further away than the severity allows: 30 days for critical, 90 for high, a year otherwise. The decision itself is **immutable**: the application's database role may update only how an acceptance ended (revoked, expired or fixed), and a partial unique index allows one acceptance in force per finding. An expired acceptance reopens its finding, and the expiry check runs on every import, read and write, so it never depends on a scheduler.

:::why Why acceptance is in the database, not only in the TOML file
The gate's file-based register stops one build. An acceptance in the application is tied to the finding's history, its approver and the audit log, and it expires visibly. Since Phase 10 the file is generated from approved exceptions in the application (Chapter 11).
:::

### Findings feed security operations

New and reopened critical or high findings become security events with source *Application security scan*, at most 50 per import plus one summary event, and a fixable critical finding opens an incident. A package vulnerability with no fix opens no incident, because there is nothing to do yet. The dashboard's Vulnerabilities control, until now marked *planned*, shows measured values: open findings by severity, past-SLA count, and the last scan with its gate result.

### SBOMs

Every scan stores a CycloneDX SBOM per artifact (API image, web image, source tree) with its SHA-256. The SBOM page lists every component with its version, type, package URL and licences, searchable, with the complete document available as a download.

## The frontend

Three pages arrived in M3: **Vulnerabilities** (counts by severity, past SLA and awaiting fix; the last scan and its gate result; filters kept in the URL), **finding detail** (where it was found, the fix, the SLA, the moves allowed, risk acceptance and revocation, the scans it appeared in) and **SBOM**. Scanner text is rendered as text and links are offered only for `https:` references, because a rule message or package description is attacker-influenced input (T-VM-01).

:::lesson A new value broke an old page
M2 added the `appsec` event source and two event categories, but not to the SPA's runtime validators. After the first import, the Threats page refused to load, exactly as a validator should when the server sends something unexpected. A backend test now compares every enumeration with the SPA's lists, so CI fails on drift instead of a page failing in use.
:::

## What the first scans found

| Scan | Result |
|---|---|
| SCAN-0001 | 174 findings recorded; the gate blocked on CVE-2026-4775 (`tiff`, fix published that day) |
| SCAN-0002 | 4 findings fixed automatically after the build-time OS upgrade; the gate passed |
| SCAN-0003 | 8 new DAST findings (low and informational) after the first authenticated scan; the gate passed |

Forty-four high package vulnerabilities in the Debian 13 base have no fix published. They are reported on every scan and will block the day a fix appears. The remedy for most of them is a smaller base image (distroless or Alpine for the API), planned with Phase 12 hardening.
