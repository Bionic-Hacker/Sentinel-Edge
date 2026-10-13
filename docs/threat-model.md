# SentinelEdge threat model

- **Version:** 0.13 (Phase 5 released: the edge applied and verified in the deploy window; account
  recovery through an administrator only, ADR-0028; the edge read back, ADR-0029)
- **Method:** STRIDE per trust boundary, with OWASP Top 10 (2021), OWASP API Security Top 10
  (2023), and OWASP Top 10 for LLM Applications (2025) as threat catalogues. Since Phase 10
  this document is loaded into the application as SentinelEdge's own threat model, read-only
  there (ADR-0022); models for other applications, STRIDE or PASTA, are built in the app.
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
| A14 | Threat models, the control catalogue and the posture score | A wrong model or an inflated score hides risk from the people deciding on it |
| A15 | Security exceptions and change requests | The record of who accepted which risk, and who approved which change, until when |
| A16 | AI analyses and proposals | What the AI said about an attack and what it asked a human to do; an altered record hides a manipulated answer |
| A17 | The AWS account: its audit trail, guardrails, network and spend | The trail is the record of every change; the guardrails and network decide what can be exposed; spend is the one harm a demo can do without an attacker |

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
| F10 | Approved exceptions → accepted-risk register → scan gate | Scan-finding exceptions exported to `scanning/accepted-findings.toml` and committed | TB4, TB8 |

## 3. Threats

### TB1 — Internet → Edge

| ID | STRIDE | Threat | L×I | Control(s) | Control IDs | Status |
|---|---|---|---|---|---|---|
| T-EDGE-01 | D | Volumetric / L7 flood | 2×2 | Shield Standard and CloudFront absorb volume; WAF rate rules per IP (sign-in 100, API 2000 per 5 minutes), the app's own limiter behind them (`modules/waf`) | C-WAF-01, C-WAF-03 | **Mitigated (P5)**: Shield Standard, WAF rate rules and the app limiter; verified in the deploy window (`make edge-check`) |
| T-EDGE-02 | T/I | TLS downgrade or weak ciphers | 1×3 | `TLSv1.2_2021` viewer policy, HTTP redirected (refused for the API), HSTS two years; `.dev` is HSTS-preloaded | C-EDGE-01, C-WEB-01 | **Mitigated (P1, P5)**: HSTS in the app; `TLSv1.2_2021` and redirects at the edge, verified in the deploy window (`make edge-check`) |
| T-EDGE-03 | E | **Origin bypass** around CloudFront/WAF | 2×3 | Internal ALB with no public address; its only ingress is CloudFront's VPC-origin security group (ADR-0001, ADR-0026, ADR-0027); `make edge-check` proves it unreachable | C-EDGE-02 | **Mitigated (P4, P5)**: the ALB resolves only to private addresses and is unreachable from the internet, verified in the deploy window (`make edge-check`) |
| T-EDGE-04 | T | Cache poisoning / cache deception | 1×3 | `/api/*` never cached at the edge (CachingDisabled), `Cache-Control: no-store`, Host allow-list; only hashed assets are long-cached | C-EDGE-03, C-API-07, C-WEB-01 | **Mitigated (P1, P5)**: `/api/*` never cached, Host allow-list, hashed assets only long-cached; verified in the deploy window (`make edge-check`) |
| T-EDGE-05 | S | Host header injection | 2×2 | TrustedHostMiddleware, no wildcards | C-API-07 | **Mitigated (P1)** |
| T-EDGE-06 | T | Clickjacking, MIME sniffing, XSS via missing headers | 2×2 | Security headers on every response; CloudFront's policy is identical to nginx's (`test_edge_headers_match_nginx`) | C-WEB-01, C-WEB-02, C-WEB-04, C-EDGE-03 | **Mitigated (P1, P5)**: CloudFront's headers identical to nginx's, verified in the deploy window (`make edge-check`) |
| T-EDGE-07 | I | The SPA bucket read directly, around CloudFront and WAF | 1×2 | Private bucket, public access blocked; only this distribution may read it (OAC, `AWS:SourceArn`) | C-EDGE-04 | **Mitigated (P5)**: OAC, public access blocked; verified in the deploy window |
| T-EDGE-08 | S | The API reached through the distribution's own `*.cloudfront.net` name, outside the platform's origin and cookie scope | 1×2 | Host forwarded to the origin: the origin certificate names only the platform, and the ALB forwards only that host (`make edge-check`) | C-LB-01, C-API-07 | **Mitigated (P5)**: no API under the distribution's own name, verified in the deploy window (`make edge-check`) |
| T-EDGE-09 | T/I | Attacker-written text in WAF log records (paths, query strings, user agents) shown to operators or sent to the AI | 2×2 | Stored as bounded, redacted, control-character-free evidence and rendered as text only; the AI receives it as delimited, untrusted data (ADR-0029) | C-EDGE-05, C-SO-02, C-AI-04 | **Mitigated (P5)** |
| T-EDGE-10 | D | An edge or origin certificate expires or fails to renew unnoticed | 1×3 | ACM renews automatically; the API reads both certificates on every sync and raises a certificate event 30 days before expiry, on a failed renewal or a bad status (ADR-0029) | C-EDGE-06 | **Mitigated (P5)**: both certificates read and checked in the deploy window |
| T-EDGE-11 | E | The API's new read access to AWS abused or widened | 1×2 | Read-only and narrow: `logs:FilterLogEvents` on the one WAF log group, ACM list and describe (metadata, never keys); nothing that changes WAF, logs or certificates; tested in `modules/ecs` | C-EDGE-05, C-EDGE-06, C-WAF-04 | **Mitigated (P5)** |

### TB2 — Edge → Origin

| ID | STRIDE | Threat | L×I | Control(s) | Control IDs | Status |
|---|---|---|---|---|---|---|
| T-ORG-01 | I | Plaintext CloudFront→origin traffic | 1×2 | HTTPS-only listener on the ALB, TLS 1.3/1.2 with forward-secret ciphers, the ACM certificate for the platform's name (`modules/alb`) | C-LB-01, C-EDGE-02 | **Mitigated (P4)**: HTTPS-only internal ALB, verified in the deploy window |
| T-ORG-02 | S | Spoofed `X-Forwarded-For` to evade IP controls | 2×2 | Proxy-header trust only from configured proxy networks, chain walked right to left | C-NET-03 | **Mitigated (P4, P6)**: proxy headers trusted only from the app subnets (ALB, CloudFront's VPC origin) and the local proxy network |
| T-ORG-03 | T | HTTP request smuggling / desync | 1×3 | ALB desync mitigation "strictest", drop invalid headers; other host names refused at the ALB (`modules/alb`) | C-LB-01 | **Mitigated (P4)**: verified in the deploy window |

### TB3 — Browser session → API

| ID | STRIDE | Threat | OWASP | L×I | Control(s) | Control IDs | Status |
|---|---|---|---|---|---|---|---|
| T-ID-01 | S | Credential stuffing / brute force | API2, A07 | 3×3 | WAF rate rule, app limiter, lockout, MFA, detection | C-ID-04, C-ID-05, C-API-03, C-SO-04, C-WAF-03 | **Mitigated (P2, P5, P6) and detected (P7)**: lockout, MFA, uniform errors, per-IP sign-in limits, the WAF sign-in rate rule; COR-001, COR-002 and COR-007 open incidents |
| T-ID-02 | S | Access-token theft via XSS | A03 | 2×3 | Memory-only token, strict CSP, React escaping, ESLint bans | C-ID-09, C-WEB-02, C-WEB-03 | **Mitigated (P2)**: token in memory only, refresh cookie HttpOnly (verified in Chromium) |
| T-ID-03 | S | Refresh-token replay | API2 | 2×3 | Rotation with family revocation (ADR-0003) | C-ID-03 | **Mitigated (P2)**: reuse revokes the session and is audited; opens a token-theft incident (P7) |
| T-ID-04 | T | CSRF on cookie-authenticated refresh | A01 | 2×2 | SameSite=Strict, Origin check, custom header | C-ID-03, C-ID-06 | **Mitigated (P2)** |
| T-ID-05 | I | Account enumeration | API2 | 3×1 | Generic auth errors, uniform timing | C-ID-05 | **Mitigated (P2)**: identical responses, dummy hash for unknown accounts; no public reset or invitation endpoint (ADR-0028) |
| T-API-01 | E | BOLA (object-level authorization) | API1 | 3×3 | Service-level ownership checks, UUID IDs | C-API-01 | **Mitigated (P2, P7)**: user records; applications (developers see only their own, others 404 and audited); repeated denials raise COR-004 |
| T-API-02 | E | BFLA (function-level authorization) | API5 | 2×3 | Role dependencies on every route; route-table test | C-API-02 | **Mitigated (P2)**: declared matrix + enforcement sweep |
| T-API-03 | T | Mass assignment | API3 | 2×3 | `extra="forbid"` request models | C-API-04, C-API-11 | **Mitigated (P2)**: all request models; tested on login and user admin |
| T-API-04 | D | Unrestricted resource consumption | API4 | 3×2 | WAF rate rules, app limits, body size limit, pagination caps | C-API-03, C-WAF-03 | **Mitigated (P5, P6)**: token buckets per IP and account, page caps, body limit, statement timeout; WAF rate rules at the edge |
| T-API-05 | I | Excessive data exposure | API3 | 2×3 | Explicit response models (ADR-0012) | C-API-11 | **Mitigated (P2)**: user responses checked against an exact field allow-list |
| T-API-06 | I | Unauthenticated capability endpoint discloses roadmap | API9 | 1×1 | Moved behind authentication | C-API-02 | **Closed (P2)** |
| T-API-07 | T | Injection (SQL, command) | API8, A03 | 2×3 | ORM parameterisation, validation, WAF SQLi rules, detection | C-API-04, C-CICD-07, C-SO-02, C-WAF-01 | **Mitigated (P2, P5), detected (P7)**: ORM only, validated query params; AWS WAF's SQL injection rules block at the edge (verified); 17 detect-only HTTP rules and COR-003 behind it |
| T-API-08 | I | SSRF via user-supplied URLs | API7 | 1×3 | No server-side fetch of user URLs; egress guard (HTTPS, allow-list, public addresses only) | C-API-12 | **Not exposed; guard ready and tested (P6)** |
| T-API-09 | I | Error messages leak stack traces, SQL, paths, secrets | API8 | 2×2 | Generic envelope, no input echo, internal logging | C-API-06 | **Mitigated (P1, tested)** |
| T-API-10 | R | Requests untraceable during investigation | — | 2×2 | Correlation IDs, structured logs | C-LOG-01 | **Mitigated (P1)** |
| T-API-11 | T | Log injection / forging | — | 2×2 | JSON logging, control-char neutralisation, ID allow-list | C-LOG-02 | **Mitigated (P1, tested)** |
| T-API-13 | D | Flood of throttled requests fills the audit log | API4 | 2×2 | Only the first denial in a run is audited; later ones are counted | C-API-03 | **Mitigated (P6, tested)** |
| T-API-12 | I | Improper inventory: undocumented or debug endpoints | API9 | 2×2 | Docs disabled in deployed envs; inventory from route table | C-API-08, C-API-09, C-API-10 | **Mitigated (P1, P6)**: registry must equal the route table; unknown-path probes counted |

### Identity threats added in Phase 2

| ID | STRIDE | Threat | L×I | Control(s) | Control IDs | Status |
|---|---|---|---|---|---|---|
| T-ID-06 | D | Two browser tabs refresh at once, tripping reuse detection (self-inflicted logout) | 2×1 | Web Locks serialize refresh across tabs | C-ID-09 | **Mitigated (P2)** |
| T-ID-07 | S | TOTP code replayed within its validity window | 2×3 | Last accepted step stored; strictly increasing | C-ID-04 | **Mitigated (P2)** |
| T-ID-08 | I | Database dump yields working second factors | 1×3 | TOTP secrets Fernet-encrypted with a key outside the DB; recovery codes hashed | C-ID-04 | **Mitigated (P2)** |
| T-ID-09 | E | Default or shared bootstrap credentials | 2×3 | No defaults: `create-admin` one-time password; administrators issue generated temporary passwords, never choose them | C-ID-08, C-ID-07 | **Mitigated (P2, P5)** |
| T-ID-10 | D | Attacker locks out a known account by failing logins | 2×1 | Lockout is temporary; WAF/IP limits will throttle the attacker | C-ID-05, C-API-03 | **Accepted**: per-IP sign-in limits (P6) and the WAF sign-in rate rule (P5) bound it; a distributed attacker can still trigger the 15-minute lockout. WAF Bot Control not adopted (cost, ADR-0027) |
| T-ID-11 | S | Account recovery hijacked: a reset or invitation link read from a compromised mailbox, or a self-service reset abused | 2×3 | No email path at all: accounts and forgotten passwords go through an administrator, who must be contacted (ADR-0028) | C-ID-07 | **Mitigated (P5)** |
| T-ID-12 | I | A temporary password seen or kept while it is handed over | 2×2 | Generated, shown once and never stored in plain text, logged or audited; expires after 72 hours; replaced at first sign-in; MFA still required for privileged roles | C-ID-07, C-ID-08 | **Mitigated (P5)**; the hand-over channel is the owner's choice (residual risk) |
| T-INP-01 | D | Non-ASCII digits pass `\d` validation and crash a comparison (500) | 2×1 | ASCII-only `[0-9]`; regression test | C-API-04 | **Mitigated (P2)** — found by the test suite |
| T-AZ-01 | E | Role compared by identity (`is`) against a string from the DB, silently failing open or closed | 2×3 | Enum-typed column; `==` comparisons; authorization sweep | C-API-02 | **Mitigated (P2)** — found by the test suite |

### Security operations threats added in Phase 7

| ID | STRIDE | Threat | L×I | Control(s) | Control IDs | Status |
|---|---|---|---|---|---|---|
| T-SO-01 | T/R | Incident evidence or timeline altered to hide an intrusion or a mishandled response | 2×3 | Events append-only for the app role; `incident_id` write-once (trigger); timeline append-only with each entry's SHA-256 in the audit chain, verified on every read; incidents never deleted (ADR-0018) | C-SO-01, C-SO-06 | **Mitigated (P7, tested)** |
| T-SO-02 | T | Simulated activity mixed into real detections, incidents or dashboards | 2×3 | Provenance on every record; correlation partitioned by provenance; live and simulated views never combined; simulated banner (ADR-0009, ADR-0019) | C-SO-04, C-SO-08, C-GOV-01 | **Mitigated (P7, tested)** |
| T-SO-03 | D | Attacker floods security events to bury real detections or load the database | 2×2 | Events only from security signals, not every request; HTTP-analysis recording throttled to 30 events a minute per source; a detection at most once per rule, key and window; bounded evidence; one open incident per source; rate limits | C-SO-02, C-API-03 | **Mitigated (P7)**; retention policy P12 |
| T-SO-04 | D | ReDoS: crafted input makes HTTP analysis patterns backtrack | 2×2 | Linear-time patterns, bounded input sizes, adversarial timing test | C-SO-03 | **Mitigated (P7, tested)** |
| T-SO-05 | T | Stored XSS: attack payloads in evidence rendered as markup in the dashboard | 2×3 | Evidence rendered as text only, strict CSP (no inline script or style), test with a `<script>` snippet | C-SO-09, C-WEB-02 | **Mitigated (P7, tested)** |
| T-SO-06 | E | Analyst bypasses the incident workflow (closes, reopens, reassigns beyond their role) | 2×2 | Workflow and role rules enforced on the server; UI renders `available_moves` and `permissions` only; authorization matrix tests | C-SO-05, C-API-02 | **Mitigated (P7, tested)** |
| T-SO-07 | T | Lost update: two responders overwrite each other's changes | 2×1 | Optimistic concurrency (`version`); stale writes get 409 and a reload prompt | C-SO-07 | **Mitigated (P7, tested)** |
| T-SO-08 | E | Attack simulator abused to attack another system | 1×3 | No network I/O and no target input; RFC 5737 addresses and `.example` names; leads only; every run audited and rate limited (ADR-0019) | C-SO-08 | **Mitigated (P7, tested)** |
| T-SO-09 | I | Passwords, tokens or codes captured in event evidence | 2×3 | Snippets from sensitive fields replaced with `[REDACTED]`; bounded snippets; incident free text excluded from inspection | C-SO-02, C-LOG-02 | **Mitigated (P7, tested)** |

### Application security threats added in Phase 8

| ID | STRIDE | Threat | L×I | Control(s) | Control IDs | Status |
|---|---|---|---|---|---|---|
| T-VM-01 | T | Scanner output (package metadata, rule messages, URLs) carries markup or terminal escapes into the UI or logs | 2×2 | Every imported string bounded and control characters replaced; rendered as text only; links only for `https:` references | C-VM-04, C-SO-09 | **Mitigated (P8, tested)** |
| T-VM-02 | R | A risk acceptance used to silence a finding indefinitely, or rewritten after approval | 2×3 | Leads only; justification, compensating control and expiry within the severity limit; decision immutable (column grants); one in force per finding; expiry reopens the finding; audited | C-VM-03 | **Mitigated (P8, tested)** |
| T-VM-03 | T | A finding marked fixed without a fix (by hand, or by a partial scan) | 2×3 | "Fixed" only from a scan that ran every report able to produce the finding; no API move to fixed; a returning finding reopens | C-VM-01 | **Mitigated (P8, tested)** |
| T-VM-04 | E | The scan gate passes because a scanner crashed or wrote nothing | 2×3 | Gate fails closed: every expected report required (`--expect`), unreadable reports and an empty scan exit 2 | C-CICD-08 | **Mitigated (P8, tested)** |
| T-VM-05 | T | A compromised or swapped scanner image | 1×3 | Images pinned by tag and digest; run as the calling user, repository read-only, no Docker socket; Checkov offline, Semgrep metrics off | C-CICD-09 | **Mitigated (P8)** |
| T-VM-06 | T | Authenticated DAST changes or destroys platform data | 2×2 | Scanner account is a VIEWER without a usable password; one 60-minute session per scan, revoked at the end; logout excluded from the target document; local stack only | C-CICD-11 | **Mitigated (P8, tested)** |
| T-VM-07 | I | Developers read other teams' findings (a map of their weaknesses) | 2×2 | Object-level filter on findings, scans and SBOMs; other IDs 404 and audited | C-API-01 | **Mitigated (P8, tested)** |
| T-VM-08 | D | A large or hostile import exhausts the API or floods the event store | 1×2 | 64 MB stdin cap, 20,000 findings and components per import, at most 50 events per import, CLI-only (no upload endpoint) | C-VM-04, C-VM-05 | **Mitigated (P8)** |

### Governance threats added in Phase 10

| ID | STRIDE | Threat | L×I | Control(s) | Control IDs | Status |
|---|---|---|---|---|---|---|
| T-GOV-01 | E/R | Whoever requests an exception or a change approves it themselves | 2×3 | Separation of duties in the service (409 `separation_of_duties`) and a database CHECK; a second lead account is required (ADR-0023) | C-GOV-03, C-GOV-04 | **Mitigated (P10, tested)** |
| T-GOV-02 | T/R | A decision rewritten after the fact, or a rejected or cancelled request revived | 2×3 | Triggers make decisions final; the app role cannot delete governance records; history read from the hash-chained audit log | C-GOV-08, C-AUD-01 | **Mitigated (P10, tested)** |
| T-GOV-03 | R | An accepted risk outlives its justification | 2×2 | Expiry within the risk's limit; expiry on the date without a scheduler; the gate's register generated from approved exceptions, so an expired one stops covering its finding | C-GOV-04, C-GOV-09 | **Mitigated (P10, tested)** |
| T-GOV-04 | T | The threat model or control catalogue in the application drifts from the reviewed documents, or cites evidence that does not exist | 2×2 | Catalogue generated from the documents and checked by a test; cited tests and targets must exist; SentinelEdge's model read-only in the app | C-GOV-06, C-GOV-01 | **Mitigated (P10, tested)** |
| T-GOV-05 | T | A posture score that cannot be explained, or counts planned controls as built, misleads decisions | 2×2 | Coverage from implemented controls only; every deduction names its records; the method is returned with the score; planned categories score 0 | C-GOV-10 | **Mitigated (P10, tested)** |
| T-GOV-06 | I | Developers read other teams' threat models and exceptions | 2×2 | Object-level filter on models, exceptions and change requests; other IDs 404 and audited | C-API-01 | **Mitigated (P10, tested)** |
| T-GOV-07 | T/R | A threat model deleted to hide known threats, or by a role that should not | 2×2 | Archive offered first (leads, developers on their own applications); permanent deletion leads only, audited with a summary of the model and its threats; SentinelEdge's own model cannot be removed | C-GOV-07, C-API-02 | **Mitigated (P10, tested)** |
| T-GOV-08 | E | A change request used to change the real WAF outside Terraform | 1×3 | A `waf_rule` change drives only the simulated WAF; real rules change through reviewed Terraform with read-only app access (ADR-0008) | C-GOV-03, C-WAF-04 | **Mitigated (P5, P10)**: the simulated WAF changes simulations only; the real one only through reviewed Terraform |
| T-GOV-09 | T | Stored XSS through threat, exception or change text | 2×3 | Everything people typed rendered as text only, under the strict CSP | C-SO-09, C-WEB-02 | **Mitigated (P10, tested)** |

### TB4 — API → Database

| ID | STRIDE | Threat | L×I | Control(s) | Control IDs | Status |
|---|---|---|---|---|---|---|
| T-DB-01 | I | Database exposed to the internet | 1×3 | Isolated subnets, `publicly_accessible=false`, SG, Checkov | C-NET-00, C-NET-01, C-NET-02 | **Mitigated (P1, P3, P4)**: RDS in isolated subnets, not publicly accessible, verified in the deploy window |
| T-DB-02 | I | Credential theft | 2×3 | Per-container secrets; Secrets Manager with rotation in AWS | C-SEC-03 | **Mitigated (P2, P4)**: Secrets Manager, one execution role per task reading only its own secrets |
| T-DB-03 | E | Over-privileged app DB role | 2×3 | Separate migration and runtime roles (ADR-0015) | C-DB-01 | **Mitigated (P2)**: privilege-matrix test |
| T-DB-04 | I | Unencrypted data at rest or in transit | 1×3 | KMS, `rds.force_ssl`, TLS 1.2 minimum; the app verifies the server certificate and host name against Amazon's CA bundle (`verify-full`) | C-DB-02, C-DB-03 | **Mitigated (P4)**: verified in the deploy window |

### TB5 — API → AI provider (and attacker data into the AI)

| ID | STRIDE / LLM | Threat | L×I | Control(s) | Control IDs | Status |
|---|---|---|---|---|---|---|
| T-AI-01 | LLM01 | Direct prompt injection by an analyst | 2×2 | Only an allow-list of record fields reaches the model (no free-text prompt); prompt-risk scoring; delimiting | C-AI-01 | **Mitigated (P9, tested)**: there is no prompt box; analysts choose a record, not the words |
| T-AI-02 | LLM01 | **Indirect** injection via request content, user agents, log lines or finding text | 3×2 | Data delimited under a per-call nonce; signals scored and shown; verbatim-evidence contract; tighten-only proposals that a lead approves (ADR-0007, ADR-0024) | C-AI-01, C-AI-02, C-AI-05 | **Mitigated (P9, tested)**: a fully obedient model can only produce a rejected answer or a reviewable proposal |
| T-AI-03 | LLM05 | Insecure output handling (XSS through AI text or quoted payloads) | 2×3 | Rendered as text only under the strict CSP; never executed or used in queries; responses validated by the SPA | C-AI-03, C-WEB-02 | **Mitigated (P9, tested)** |
| T-AI-04 | LLM02 | Sensitive data sent to or leaked by the model | 2×2 | Allow-listed, bounded fields; addresses and e-mails pseudonymised; redacted evidence; Bedrock does not train on inputs | C-AI-04 | **Mitigated (P9, tested)** |
| T-AI-05 | LLM06 | Excessive agency: AI performs or triggers a destructive action | 1×3 | No tools; three proposal types, tighten-only; a lead approves and the action runs as that person; decisions final | C-AI-05 | **Mitigated (P9, tested)** |
| T-AI-06 | LLM10 | Unbounded consumption (cost) | 2×2 | Limits checked before any call (per user per day, platform tokens per day, tokens per answer); viewers cannot run analyses; every call audited | C-AI-06 | **Mitigated (P9, tested)** |
| T-AI-07 | LLM09 | Fabricated evidence: the model presents an invention as an observed fact | 2×3 | Every observed-evidence item must be a verbatim quote of a field that was sent; inference is labelled as such; disagreements with the platform shown, never acted on | C-AI-02 | **Mitigated (P9, tested)** |
| T-AI-08 | E | A proposal used to weaken a control (a WAF rule to count, an incident closed) | 1×3 | The contract allows only opening an incident, adding a threat, or a WAF rule to block; a change request still needs a second lead | C-AI-05, C-GOV-03 | **Mitigated (P9, tested)** |
| T-AI-09 | I | AWS credentials for Bedrock leak from the developer machine or container | 1×3 | One permission on one model; short-lived session credentials in a git-ignored, mode-600 file; task role when deployed; AWS error text kept out of responses | C-AI-07, C-SEC-01 | **Mitigated (P9)** |
| T-AI-10 | T/R | An analysis or decision rewritten to hide a manipulated answer | 1×3 | Analyses insert-only for the app role; proposals final once decided (trigger); every call and decision in the hash-chained audit log with the prompt's SHA-256 | C-AI-05, C-AUD-01 | **Mitigated (P9, tested)** |

### TB6 — CI/CD → AWS, TB7 — Operators, TB8 — Developer → repo

| ID | STRIDE | Threat | L×I | Control(s) | Control IDs | Status |
|---|---|---|---|---|---|---|
| T-CICD-01 | E | Stolen long-lived cloud keys from CI | 2×3 | No stored keys. GitHub OIDC (ADR-0010) is denied by the account's SCPs, so Phase 11 must choose another keyless route or keep deployment off CI | C-IAM-02 | Planned (P11); no keys exist anywhere (P3) |
| T-CICD-02 | T | Malicious or hijacked third-party action | 1×3 | SHA-pinned actions, read-only token, Dependabot | C-CICD-03 | **Mitigated (P1)** |
| T-SC-01 | T | Vulnerable or malicious dependency | 2×3 | Hash-pinned Python deps, lockfile npm, pip-audit, npm audit, `--ignore-scripts`; Trivy (lock files and images), Syft SBOMs per scan, OS fixes applied at image build, digest-pinned base images | C-CICD-02, C-CICD-06, C-CICD-10 | **Mitigated (P1, P8)** |
| T-SEC-01 | I | Secret committed to git | 2×3 | Gitleaks pre-commit + CI (full history), `.gitignore` | C-SEC-01, C-SEC-02 | **Mitigated (P1)** |
| T-SEC-03 | I | A new administrator's one-time password left in a task's log (kept a year) | 1×3 | In a deployed environment `create-admin` writes it to one Secrets Manager secret and refuses to print it; the task's role can write that secret but not read it | C-SEC-04 | **Mitigated (P5)**: the administrator's one-time password read once from Secrets Manager in the deploy window, never in a log |
| T-SEC-02 | I | Secrets readable from Terraform plans, state or logs (anyone with the state bucket or a CI log gets the database passwords and signing keys) | 1×3 | The RDS master password generated and held by RDS; application secrets generated during apply as ephemeral values and written through write-only arguments, never stored in state (ADR-0026) | C-SEC-04 | **Mitigated (P4)**: no secret value in any plan or state of the deploy window |
| T-IAC-01 | T | Dev change applied to production | 1×3 | Per-stack roots and state keys, `allowed_account_ids` (ADR-0014) | C-IAC-01 | **Mitigated (P3)** |
| T-IAC-02 | I | Terraform state disclosure | 1×3 | Encrypted, private, versioned state bucket | C-IAC-02 | **Mitigated (P3)** |
| T-IAC-03 | T | An unreviewed or stale plan applied, or a plan applied to the wrong account or as root | 1×3 | Saved-plan-only apply, identity and account guard, root refused | C-IAC-03, C-IAC-01 | **Mitigated (P3)** |
| T-IAC-04 | T | Insecure infrastructure merged unnoticed (public bucket, open group, unencrypted volume, egress from the data tier) | 2×3 | Checkov in the scan gate, TFLint, module tests with a mocked provider | C-IAC-04 | **Mitigated (P3)** |
| T-AWS-01 | I | A bucket made public by mistake | 1×3 | Account-wide S3 public-access block, per-bucket blocks, TLS-only policies | C-AWS-01 | **Mitigated (P3)** |
| T-AWS-02 | R | Account activity hidden: the trail stopped, changed or its logs altered | 1×3 | Multi-region trail, digest validation, KMS, versioned bucket; alarm on any trail change | C-LOG-04, C-MON-02 | **Mitigated (P3)** |
| T-AWS-03 | E | The root user or a full-access session used where less would do, including a session copied into a container | 2×3 | No root (Builder ID); `tf.sh` refuses root; root-use alarm; the local API gets a one-model role, never the signed-in session | C-IAM-01, C-MON-02, C-AI-07 | **Mitigated (P3)** |
| T-COST-01 | D | Runaway spend ("denial of wallet"): a forgotten NAT, ALB or database, or abuse of a paid API | 2×2 | Credit ceiling (Free plan), budget alerts, nothing hourly at rest, one deploy window then destroy; AI quotas (C-AI-06) | C-COST-01, C-AI-06 | **Mitigated (P3)** |
| T-DNS-01 | S | A certificate issued for the platform's name by someone else, or the name taken over (including through a delegation left pointing at a deleted Route 53 zone) | 1×3 | CAA allows only Amazon and no wildcards; exact-name certificates; a domain held by the owner; the zone is `prevent_destroy` and the teardown removes the delegation first | C-DNS-01, C-DNS-02 | **Mitigated (P3, P5)**: CAA and records as code; every query logged (P5) |
| T-WAF-01 | T | WAF rule disabled without review | 2×3 | Terraform-only changes from reviewed plans, PR approval; rule tests in `modules/waf` | C-WAF-04, C-GOV-02, C-GOV-03 | **Mitigated (P5)**: Terraform-only, from reviewed plans; verified in the deploy window |
| T-WAF-02 | E | Compromised app used to weaken WAF | 1×3 | The API's task role has no WAF permissions at all (ADR-0008, ADR-0026) | C-WAF-04, C-IAM-01 | **Mitigated (P5)**: the task role reads the WAF log and nothing else of WAF (ADR-0029) |
| T-AUD-01 | R | Audit records altered or deleted | 2×3 | Hash chain, INSERT-only grants, triggers, Object Lock (ADR-0005) | C-AUD-01, C-AUD-02, C-AUD-03 | **Mitigated (P2, P4)**: hash chain, plus hourly anchors of its head in S3 Object Lock; `audit-anchor check` verified in the deploy window |
| T-CNT-01 | E | Container breakout / privilege escalation | 1×3 | Non-root, read-only FS, `cap_drop: ALL`, no-new-privileges | C-CNT-01 | **Mitigated (P1, local)** |

## 4. Attack paths (top three)

1. **Origin bypass → unfiltered injection.** Attacker finds the origin, sends payloads that WAF
   would block. Broken by ADR-0001 (no public origin) and by app-layer validation and
   parameterisation, which hold even without WAF.
2. **Credential stuffing → session theft → data access.** Broken at the WAF rate rule, app lockout,
   MFA, short-lived tokens, and RBAC/object checks; detected by COR-001 (stuffing), COR-007 (a
   sign-in from the stuffing source) and token-replay incidents (Phase 7).
3. **Poisoned log line → AI recommends harmful change → operator applies it.** Broken because the
   data is delimited and scored (T-AI-02), evidence must be quoted verbatim (T-AI-07), proposals
   can only tighten controls and need a lead's approval (T-AI-05, T-AI-08), and real WAF changes
   need a Terraform PR with review.

## 5. Residual risk (after Phase 5)

- Single-maintainer project: separation of duties is enforced by role checks and a database
  CHECK, so it needs two lead accounts, but both belong to the same person. Accepted for a
  portfolio.
- The edge exists only during a deploy window: between windows nothing is served, and the local
  stack is bound to 127.0.0.1 and must not be exposed.
- The AWS account's guardrail policies (SCPs) are written by AWS and cannot be read or changed here.
  They deny IAM Access Analyzer and OIDC identity providers; anything else they deny is found when
  a plan is applied. Accepted: it is the price of a spend-capped, root-less account.
- No keyless route from GitHub Actions into the account (OIDC denied): deployments run from the
  owner's machine with a 12-hour `aws login` session. Phase 11 decides how CI deploys.
- One NAT for both zones in dev: a zone outage takes egress with it. Accepted for a demo.
- Audit-log tail deletion by someone with table-owner rights is detectable only while anchors are
  being written, that is during a deploy window (hourly, S3 Object Lock, ADR-0026). Locally the
  verify output's head hash is the only anchor.
- One HS256 signing key without `kid`: rotation signs everyone out (ADR-0003 addendum).
- Account recovery needs an administrator (ADR-0028): a user who forgets their password waits
  for one, and the temporary password is only as private as the channel it is handed over in
  (T-ID-12). Accepted: it expires in 72 hours and must be replaced at first sign-in.
- Deliberate lockout of a known account (T-ID-10) is now bounded per IP (20 sign-in attempts per
  2 minutes) and at the edge (100 sign-in requests per 5 minutes), but a distributed attacker
  can still trigger the per-account lockout. WAF Bot Control ($10 a month plus requests) is not
  adopted. Accepted: lockout expires after 15 minutes.
- Rate-limit and metrics writes add database load per request (ADR-0017). Revisited in Phase 12.
- Rate-limit state is per database: a database outage disables sign-in entirely (fails closed).
- Correlation for audit-fed events (failed sign-ins, denials) runs inside the request that
  produced them (ADR-0018), so an attack burst adds a little latency to those requests; HTTP
  analysis runs after the response. Bounded by the rate limiter; revisited in Phase 12.
- Security events and incidents have no retention policy yet; they grow until Phase 12 adds one.
- HTTP analysis is detect-only. In AWS, WAF blocks known injection payloads at the edge; locally
  and between windows, parameterised queries and validation are the protection, and detection
  records it.
- On one machine every request comes from one address, so local detections group into a single
  incident. Expected; not a weakness of the deployed design.
- The Debian 13 base of the API image carries high OS package vulnerabilities with no fix
  published (44 at the end of Phase 8). They are reported on every scan and block as soon as a
  fix exists; most are in packages the service never executes. A minimal base image (distroless
  or Alpine) is planned with Phase 12 hardening.
- The scan gate reads a committed file (`scanning/accepted-findings.toml`) generated from the
  approved exceptions (`make accepted-risks`). Between a decision and the next generation the
  gate uses the previous file; run it after every scan-finding decision. Finding-level risk
  acceptances (Phase 8) and exceptions remain two records with different scopes.
- Permanently deleting an application threat model removes its rows; the audit log keeps a
  summary (counts and the first 50 threats), not the whole model. Archive is offered first.
- Prompt-risk scoring is a set of patterns: it names likely injection attempts but can be evaded.
  It is a signal for the reviewer, not a defence; the defences are delimiting, the verbatim
  evidence contract and tighten-only proposals with human approval.
- A model can still be wrong within the contract: a correct quote with a misleading inference.
  Inference is labelled, the platform's own verdict is never changed, and nothing runs without a
  lead's approval.
- The offline analyser is deterministic and not a model; it proves the engine, not the quality of
  a real model's answers. Bedrock answers vary between runs (temperature 0 narrows, not removes).
- Limits are per day and counted from stored analyses; a burst within the limit is allowed.
  Bedrock spend is also bounded by the AWS budget alert the setup asks for.
- The posture score is computed on request and snapshotted once a day on the first read; with
  no scheduler, a day nobody opens it has no snapshot.
- Scans are imported by an operator (`make scan-import`); CI results reach SentinelEdge only when
  someone imports the CI artifact, until a deployed API can receive them (Phase 11).
- DAST covers the local stack only. The deployed edge was proven with `make edge-check`; a ZAP scan
  of it moves to the Phase 12 deploy window.
