# SentinelEdge threat model

- **Version:** 0.5 (Phase 8: application security scanning and vulnerability management)
- **Method:** STRIDE per trust boundary, with OWASP Top 10 (2021), OWASP API Security Top 10
  (2023), and OWASP Top 10 for LLM Applications (2025) as threat catalogues. Full PASTA
  treatment and in-app modelling arrive in Phase 10.
- **Review trigger:** any change to a trust boundary, data flow, or role; at the end of every phase.

Risk = Likelihood (1–3) × Impact (1–3). Status: **Mitigated** (control implemented and
tested), **Planned (Pn)**, or **Accepted (interim)** with an expiry.

## 1. Assets

| ID | Asset | Why it matters |
|---|---|---|
| A1 | User credentials, MFA secrets, refresh tokens | Account takeover, privilege escalation |
| A2 | Security telemetry (events, incidents, findings) | Reveals defensive posture and weaknesses |
| A3 | Audit log | Accountability; tampering hides attacker actions |
| A4 | WAF and edge configuration | Weakening it disables the outer defense |
| A5 | AWS credentials and IAM roles | Full environment compromise |
| A6 | Secrets (DB credentials, JWT signing key) | Forging sessions, data access |
| A7 | Source, pipeline, container images | Supply-chain compromise |
| A8 | AI prompts and outputs | Manipulated analysis, data leakage |
| A9 | Terraform state | May contain sensitive values and resource details |
| A10 | Incident records and timelines | The evidence trail of an attack and of the response to it |
| A11 | Simulated WAF configuration | Changes what simulations show; must never be mistaken for real edge state |
| A12 | Vulnerability records, risk acceptances and SBOMs | A map of known weaknesses; an altered acceptance hides a risk someone decided to carry |
| A13 | Scanner images and the scan gate | A compromised scanner or a silently failed scan lets vulnerable code ship |

## 2. Trust boundaries and data flows

```
[Internet user / attacker]
   │ TB1 ── Internet → Edge (CloudFront + WAF)
   ▼
[CloudFront]
   │ TB2 ── Edge → Origin (VPC origin → internal ALB)
   ▼
[API on ECS] ──TB5── [AI provider: Bedrock]
   │ TB3 ── Browser session → API (authn/authz)
   │ TB4 ── API → Database
   ▼
[RDS]
Out-of-band:  TB6 ── CI/CD → AWS     TB7 ── Operator/admin → platform & AWS
              TB8 ── Developer workstation → repository
```

| Flow | From → To | Data | Boundaries |
|---|---|---|---|
| F1 | Browser → SPA (S3) | Static assets | TB1 |
| F2 | Browser → API | Credentials, tokens, queries, analyst input | TB1, TB2, TB3 |
| F3 | API → DB | All persistent data | TB4 |
| F4 | API/worker → Bedrock | Redacted event data, prompts | TB5 |
| F5 | WAF logs → worker | Attacker-controlled request data | TB1→TB5 (indirect) |
| F6 | GitHub Actions → AWS | Images, Terraform plans | TB6 |
| F7 | Developer → GitHub | Code, configuration | TB8 |
| F8 | API → security events → correlation → incidents | Attacker-controlled request data (bounded, redacted) | TB3→TB4 |
| F9 | Attack simulator → security events | Synthetic requests in memory, labelled SIMULATED | TB4 (no network) |

## 3. Threats

### TB1 — Internet → Edge

| ID | STRIDE | Threat | L×I | Control(s) | Status |
|---|---|---|---|---|---|
| T-EDGE-01 | D | Volumetric / L7 flood | 2×2 | Shield Standard, WAF rate rules, CloudFront | Planned (P5) |
| T-EDGE-02 | T/I | TLS downgrade or weak ciphers | 1×3 | `TLSv1.2_2021` policy, HSTS | HSTS mitigated (app); edge P5 |
| T-EDGE-03 | E | **Origin bypass** around CloudFront/WAF | 2×3 | Internal ALB via VPC origin (ADR-0001) | Planned (P4–5) |
| T-EDGE-04 | T | Cache poisoning / cache deception | 1×3 | `/api/*` uncached, `Cache-Control: no-store`, Host allow-list | Partly mitigated (P1 headers + Host); edge P5 |
| T-EDGE-05 | S | Host header injection | 2×2 | TrustedHostMiddleware, no wildcards | **Mitigated (P1)** |
| T-EDGE-06 | T | Clickjacking, MIME sniffing, XSS via missing headers | 2×2 | Security headers on every response | **Mitigated (P1, local)**; CloudFront P5 |

### TB2 — Edge → Origin

| ID | STRIDE | Threat | L×I | Control(s) | Status |
|---|---|---|---|---|---|
| T-ORG-01 | I | Plaintext CloudFront→origin traffic | 1×2 | HTTPS listener on ALB | Planned (P4) |
| T-ORG-02 | S | Spoofed `X-Forwarded-For` to evade IP controls | 2×2 | Proxy-header trust only from configured proxy networks, chain walked right to left | **Mitigated locally (P6, tested)**: trusted local proxy network, nginx overwrites the header; ALB subnets in P4 |
| T-ORG-03 | T | HTTP request smuggling / desync | 1×3 | ALB desync mitigation "strictest", drop invalid headers | Planned (P4) |

### TB3 — Browser session → API

| ID | STRIDE | Threat | OWASP | L×I | Control(s) | Status |
|---|---|---|---|---|---|---|
| T-ID-01 | S | Credential stuffing / brute force | API2, A07 | 3×3 | WAF rate rule, app limiter, lockout, MFA, detection | **Mitigated (P2, P6) and detected (P7)**: lockout, MFA, uniform errors, per-IP sign-in limits; COR-001, COR-002 and COR-007 open incidents; WAF rate rule P5 |
| T-ID-02 | S | Access-token theft via XSS | A03 | 2×3 | Memory-only token, strict CSP, React escaping, ESLint bans | **Mitigated (P2)**: token in memory only, refresh cookie HttpOnly (verified in Chromium) |
| T-ID-03 | S | Refresh-token replay | API2 | 2×3 | Rotation with family revocation (ADR-0003) | **Mitigated (P2)**: reuse revokes the session and is audited; opens a token-theft incident (P7) |
| T-ID-04 | T | CSRF on cookie-authenticated refresh | A01 | 2×2 | SameSite=Strict, Origin check, custom header | **Mitigated (P2)** |
| T-ID-05 | I | Account enumeration | API2 | 3×1 | Generic auth errors, uniform timing | **Mitigated (P2)**: identical responses, dummy hash for unknown accounts, generic reset response |
| T-API-01 | E | BOLA (object-level authorization) | API1 | 3×3 | Service-level ownership checks, UUID IDs | **Mitigated (P2, P7)**: user records; applications (developers see only their own, others 404 and audited); repeated denials raise COR-004 |
| T-API-02 | E | BFLA (function-level authorization) | API5 | 2×3 | Role dependencies on every route; route-table test | **Mitigated (P2)**: declared matrix + enforcement sweep |
| T-API-03 | T | Mass assignment | API3 | 2×3 | `extra="forbid"` request models | **Mitigated (P2)**: all request models; tested on login and user admin |
| T-API-04 | D | Unrestricted resource consumption | API4 | 3×2 | WAF rate rules, app limits, body size limit, pagination caps | **Mitigated in app (P6)**: token buckets per IP and account, page caps, body limit, statement timeout; WAF rate rules P5 |
| T-API-05 | I | Excessive data exposure | API3 | 2×3 | Explicit response models (ADR-0012) | **Mitigated (P2)**: user responses checked against an exact field allow-list |
| T-API-06 | I | Unauthenticated capability endpoint discloses roadmap | API9 | 1×1 | Moved behind authentication | **Closed (P2)** |
| T-API-07 | T | Injection (SQL, command) | API8, A03 | 2×3 | ORM parameterisation, validation, WAF SQLi rules, detection | **Mitigated in app (P2), detected (P7)**: ORM only, validated query params; 17 detect-only HTTP rules and COR-003; WAF P5 (simulated WAF in P7) |
| T-API-08 | I | SSRF via user-supplied URLs | API7 | 1×3 | No server-side fetch of user URLs; egress guard (HTTPS, allow-list, public addresses only) | **Not exposed; guard ready and tested (P6)** |
| T-API-09 | I | Error messages leak stack traces, SQL, paths, secrets | API8 | 2×2 | Generic envelope, no input echo, internal logging | **Mitigated (P1, tested)** |
| T-API-10 | R | Requests untraceable during investigation | — | 2×2 | Correlation IDs, structured logs | **Mitigated (P1)** |
| T-API-11 | T | Log injection / forging | — | 2×2 | JSON logging, control-char neutralisation, ID allow-list | **Mitigated (P1, tested)** |
| T-API-13 | D | Flood of throttled requests fills the audit log | API4 | 2×2 | Only the first denial in a run is audited; later ones are counted | **Mitigated (P6, tested)** |
| T-API-12 | I | Improper inventory: undocumented or debug endpoints | API9 | 2×2 | Docs disabled in deployed envs; inventory from route table | **Mitigated (P1, P6)**: registry must equal the route table; unknown-path probes counted |

### Identity threats added in Phase 2

| ID | STRIDE | Threat | L×I | Control(s) | Status |
|---|---|---|---|---|---|
| T-ID-06 | D | Two browser tabs refresh at once, tripping reuse detection (self-inflicted logout) | 2×1 | Web Locks serialize refresh across tabs | **Mitigated (P2)** |
| T-ID-07 | S | TOTP code replayed within its validity window | 2×3 | Last accepted step stored; strictly increasing | **Mitigated (P2)** |
| T-ID-08 | I | Database dump yields working second factors | 1×3 | TOTP secrets Fernet-encrypted with a key outside the DB; recovery codes hashed | **Mitigated (P2)** |
| T-ID-09 | E | Default or shared bootstrap credentials | 2×3 | No defaults: `create-admin` one-time password; admins invite, never set passwords | **Mitigated (P2)** |
| T-ID-10 | D | Attacker locks out a known account by failing logins | 2×1 | Lockout is temporary; WAF/IP limits will throttle the attacker | **Accepted (interim)** until P5/P6 |
| T-INP-01 | D | Non-ASCII digits pass `\d` validation and crash a comparison (500) | 2×1 | ASCII-only `[0-9]`; regression test | **Mitigated (P2)** — found by the test suite |
| T-AZ-01 | E | Role compared by identity (`is`) against a string from the DB, silently failing open or closed | 2×3 | Enum-typed column; `==` comparisons; authorization sweep | **Mitigated (P2)** — found by the test suite |

### Security operations threats added in Phase 7

| ID | STRIDE | Threat | L×I | Control(s) | Status |
|---|---|---|---|---|---|
| T-SO-01 | T/R | Incident evidence or timeline altered to hide an intrusion or a mishandled response | 2×3 | Events append-only for the app role; `incident_id` write-once (trigger); timeline append-only with each entry's SHA-256 in the audit chain, verified on every read; incidents never deleted (ADR-0018) | **Mitigated (P7, tested)** |
| T-SO-02 | T | Simulated activity mixed into real detections, incidents or dashboards | 2×3 | Provenance on every record; correlation partitioned by provenance; live and simulated views never combined; simulated banner (ADR-0009, ADR-0019) | **Mitigated (P7, tested)** |
| T-SO-03 | D | Attacker floods security events to bury real detections or load the database | 2×2 | Events only from security signals, not every request; HTTP-analysis recording throttled to 30 events a minute per source; a detection at most once per rule, key and window; bounded evidence; one open incident per source; rate limits | **Mitigated (P7)**; retention policy P12 |
| T-SO-04 | D | ReDoS: crafted input makes HTTP analysis patterns backtrack | 2×2 | Linear-time patterns, bounded input sizes, adversarial timing test | **Mitigated (P7, tested)** |
| T-SO-05 | T | Stored XSS: attack payloads in evidence rendered as markup in the dashboard | 2×3 | Evidence rendered as text only, strict CSP (no inline script or style), test with a `<script>` snippet | **Mitigated (P7, tested)** |
| T-SO-06 | E | Analyst bypasses the incident workflow (closes, reopens, reassigns beyond their role) | 2×2 | Workflow and role rules enforced on the server; UI renders `available_moves` and `permissions` only; authorization matrix tests | **Mitigated (P7, tested)** |
| T-SO-07 | T | Lost update: two responders overwrite each other's changes | 2×1 | Optimistic concurrency (`version`); stale writes get 409 and a reload prompt | **Mitigated (P7, tested)** |
| T-SO-08 | E | Attack simulator abused to attack another system | 1×3 | No network I/O and no target input; RFC 5737 addresses and `.example` names; leads only; every run audited and rate limited (ADR-0019) | **Mitigated (P7, tested)** |
| T-SO-09 | I | Passwords, tokens or codes captured in event evidence | 2×3 | Snippets from sensitive fields replaced with `[REDACTED]`; bounded snippets; incident free text excluded from inspection | **Mitigated (P7, tested)** |

### Application security threats added in Phase 8

| ID | STRIDE | Threat | L×I | Control(s) | Status |
|---|---|---|---|---|---|
| T-VM-01 | T | Scanner output (package metadata, rule messages, URLs) carries markup or terminal escapes into the UI or logs | 2×2 | Every imported string bounded and control characters replaced; rendered as text only; links only for `https:` references | **Mitigated (P8, tested)** |
| T-VM-02 | R | A risk acceptance used to silence a finding indefinitely, or rewritten after approval | 2×3 | Leads only; justification, compensating control and expiry within the severity limit; decision immutable (column grants); one in force per finding; expiry reopens the finding; audited | **Mitigated (P8, tested)** |
| T-VM-03 | T | A finding marked fixed without a fix (by hand, or by a partial scan) | 2×3 | "Fixed" only from a scan that ran every report able to produce the finding; no API move to fixed; a returning finding reopens | **Mitigated (P8, tested)** |
| T-VM-04 | E | The scan gate passes because a scanner crashed or wrote nothing | 2×3 | Gate fails closed: every expected report required (`--expect`), unreadable reports and an empty scan exit 2 | **Mitigated (P8, tested)** |
| T-VM-05 | T | A compromised or swapped scanner image | 1×3 | Images pinned by tag and digest; run as the calling user, repository read-only, no Docker socket; Checkov offline, Semgrep metrics off | **Mitigated (P8)** |
| T-VM-06 | T | Authenticated DAST changes or destroys platform data | 2×2 | Scanner account is a VIEWER without a usable password; one 60-minute session per scan, revoked at the end; logout excluded from the target document; local stack only | **Mitigated (P8, tested)** |
| T-VM-07 | I | Developers read other teams' findings (a map of their weaknesses) | 2×2 | Object-level filter on findings, scans and SBOMs; other IDs 404 and audited | **Mitigated (P8, tested)** |
| T-VM-08 | D | A large or hostile import exhausts the API or floods the event store | 1×2 | 64 MB stdin cap, 20,000 findings and components per import, at most 50 events per import, CLI-only (no upload endpoint) | **Mitigated (P8)** |

### TB4 — API → Database

| ID | STRIDE | Threat | L×I | Control(s) | Status |
|---|---|---|---|---|---|
| T-DB-01 | I | Database exposed to the internet | 1×3 | Isolated subnets, `publicly_accessible=false`, SG, Checkov | Local analogue **mitigated (P1)**; AWS P3–4 |
| T-DB-02 | I | Credential theft | 2×3 | Per-container secrets; Secrets Manager with rotation in AWS | Local scoping **mitigated (P2)**; Secrets Manager P4 |
| T-DB-03 | E | Over-privileged app DB role | 2×3 | Separate migration and runtime roles (ADR-0015) | **Mitigated (P2)**: privilege-matrix test |
| T-DB-04 | I | Unencrypted data at rest or in transit | 1×3 | KMS, `rds.force_ssl` | Planned (P4) |

### TB5 — API → AI provider (and attacker data into the AI)

| ID | STRIDE / LLM | Threat | L×I | Control(s) | Status |
|---|---|---|---|---|---|
| T-AI-01 | LLM01 | Direct prompt injection by an analyst | 2×2 | Input validation, prompt-risk scoring | Planned (P9) |
| T-AI-02 | LLM01 | **Indirect** injection via WAF log or request content | 3×2 | Untrusted-data delimiting, output schema (ADR-0007) | Planned (P9) |
| T-AI-03 | LLM05 | Insecure output handling (XSS through AI text) | 2×3 | Render as text only; schema validation | Planned (P9) |
| T-AI-04 | LLM02 | Sensitive data sent to or leaked by the model | 2×2 | Redaction before send, Bedrock (no training), minimisation | Planned (P9) |
| T-AI-05 | LLM06 | Excessive agency: AI performs destructive action | 1×3 | No state-changing tools; human approval (ADR-0007) | Planned (P9) |
| T-AI-06 | LLM10 | Unbounded consumption (cost) | 2×2 | Per-user quotas, token caps, audit | Planned (P9) |

### TB6 — CI/CD → AWS, TB7 — Operators, TB8 — Developer → repo

| ID | STRIDE | Threat | L×I | Control(s) | Status |
|---|---|---|---|---|---|
| T-CICD-01 | E | Stolen long-lived cloud keys from CI | 2×3 | GitHub OIDC, no stored keys (ADR-0010) | Planned (P11); no keys exist in P1 |
| T-CICD-02 | T | Malicious or hijacked third-party action | 1×3 | SHA-pinned actions, read-only token, Dependabot | **Mitigated (P1)** |
| T-SC-01 | T | Vulnerable or malicious dependency | 2×3 | Hash-pinned Python deps, lockfile npm, pip-audit, npm audit, `--ignore-scripts`; Trivy (lock files and images), Syft SBOMs per scan, OS fixes applied at image build, digest-pinned base images | **Mitigated (P1, P8)** |
| T-SEC-01 | I | Secret committed to git | 2×3 | Gitleaks pre-commit + CI (full history), `.gitignore` | **Mitigated (P1)** |
| T-IAC-01 | T | Dev change applied to production | 1×3 | Per-env roots, `allowed_account_ids` (ADR-0014) | Planned (P3) |
| T-IAC-02 | I | Terraform state disclosure | 1×3 | Encrypted, private, versioned state bucket | Planned (P3) |
| T-WAF-01 | T | WAF rule disabled without review | 2×3 | Terraform-only changes, PR approval | Planned (P5) |
| T-WAF-02 | E | Compromised app used to weaken WAF | 1×3 | App holds read-only WAF permissions (ADR-0008) | Planned (P5) |
| T-AUD-01 | R | Audit records altered or deleted | 2×3 | Hash chain, INSERT-only grants, triggers, Object Lock (ADR-0005) | **Mitigated (P2)** except tail deletion by a table owner (Object Lock anchor, P4) |
| T-CNT-01 | E | Container breakout / privilege escalation | 1×3 | Non-root, read-only FS, `cap_drop: ALL`, no-new-privileges | **Mitigated (P1, local)** |

## 4. Attack paths (top three)

1. **Origin bypass → unfiltered injection.** Attacker finds the origin, sends payloads that WAF
   would block. Broken by ADR-0001 (no public origin) and by app-layer validation and
   parameterisation, which hold even without WAF.
2. **Credential stuffing → session theft → data access.** Broken at the WAF rate rule, app lockout,
   MFA, short-lived tokens, and RBAC/object checks; detected by COR-001 (stuffing), COR-007 (a
   sign-in from the stuffing source) and token-replay incidents (Phase 7).
3. **Poisoned log line → AI recommends harmful change → operator applies it.** Broken because AI
   output is schema-bound and advisory, proposals need approval, and real WAF changes need a
   Terraform PR with review.

## 5. Residual risk (after Phase 8)

- Single-maintainer project: separation of duties is enforced by role checks, not by different
  people. Accepted for a portfolio.
- No edge protection yet (WAF, TLS at the edge): the local stack is bound to 127.0.0.1 and must not
  be exposed. Closed in Phase 5.
- Audit-log tail deletion by someone with table-owner rights is not detectable until the head hash
  is anchored externally (S3 Object Lock, Phase 4). See ADR-0005 addendum.
- One HS256 signing key without `kid`: rotation signs everyone out (ADR-0003 addendum).
- Deliberate lockout of a known account (T-ID-10) is now bounded per IP (20 sign-in attempts per
  2 minutes), but a distributed attacker can still trigger the per-account lockout. Edge bot
  controls (Phase 5) reduce it further. Accepted: lockout expires after 15 minutes.
- Rate-limit and metrics writes add database load per request (ADR-0017). Revisited in Phase 12.
- Rate-limit state is per database: a database outage disables sign-in entirely (fails closed).
- Correlation for audit-fed events (failed sign-ins, denials) runs inside the request that
  produced them (ADR-0018), so an attack burst adds a little latency to those requests; HTTP
  analysis runs after the response. Bounded by the rate limiter; revisited in Phase 12.
- Security events and incidents have no retention policy yet; they grow until Phase 12 adds one.
- HTTP analysis is detect-only. Until AWS WAF (Phase 5), nothing blocks an injection payload at
  the edge; parameterised queries and validation remain the protection, and detection records it.
- On one machine every request comes from one address, so local detections group into a single
  incident. Expected; not a weakness of the deployed design.
- The Debian 13 base of the API image carries high OS package vulnerabilities with no fix
  published (44 at the end of Phase 8). They are reported on every scan and block as soon as a
  fix exists; most are in packages the service never executes. A minimal base image (distroless
  or Alpine) is planned with Phase 12 hardening.
- Accepted risks exist in two places until Phase 10: the gate's file register
  (`scanning/accepted-findings.toml`) and the in-application acceptances.
- Scans are imported by an operator (`make scan-import`); CI results reach SentinelEdge only when
  someone imports the CI artifact, until a deployed API can receive them (Phase 11).
- DAST covers the local stack only: edge behaviour (WAF, TLS) is scanned once it exists (Phase 5).
