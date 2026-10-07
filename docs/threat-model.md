# SentinelEdge threat model

- **Version:** 0.1 (Phase 1 baseline)
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
| T-ORG-02 | S | Spoofed `X-Forwarded-For` to evade IP controls | 2×2 | Proxy-header trust only from ALB subnets | Planned (P4); disabled in P1 |
| T-ORG-03 | T | HTTP request smuggling / desync | 1×3 | ALB desync mitigation "strictest", drop invalid headers | Planned (P4) |

### TB3 — Browser session → API

| ID | STRIDE | Threat | OWASP | L×I | Control(s) | Status |
|---|---|---|---|---|---|---|
| T-ID-01 | S | Credential stuffing / brute force | API2, A07 | 3×3 | WAF rate rule, app limiter, lockout, MFA | Planned (P2, P5) |
| T-ID-02 | S | Access-token theft via XSS | A03 | 2×3 | Memory-only token, strict CSP, React escaping, ESLint bans | CSP + lint **mitigated (P1)**; token handling P2 |
| T-ID-03 | S | Refresh-token replay | API2 | 2×3 | Rotation with family revocation (ADR-0003) | Planned (P2) |
| T-ID-04 | T | CSRF on cookie-authenticated refresh | A01 | 2×2 | SameSite=Strict, Origin check, custom header | Planned (P2) |
| T-ID-05 | I | Account enumeration | API2 | 3×1 | Generic auth errors, uniform timing | Planned (P2) |
| T-API-01 | E | BOLA (object-level authorization) | API1 | 3×3 | Service-level ownership checks, UUID IDs | Planned (P2, P6) |
| T-API-02 | E | BFLA (function-level authorization) | API5 | 2×3 | Role dependencies on every route; route-table test | Planned (P2, P6) |
| T-API-03 | T | Mass assignment | API3 | 2×3 | `extra="forbid"` request models | Pattern **mitigated (P1, tested)**; applied per endpoint P2+ |
| T-API-04 | D | Unrestricted resource consumption | API4 | 3×2 | WAF rate rules, app limits, body size limit, pagination caps | Body limit (nginx 1 MB) P1; rest P5–6 |
| T-API-05 | I | Excessive data exposure | API3 | 2×3 | Explicit response models (ADR-0012) | Pattern **mitigated (P1)** |
| T-API-06 | I | **Unauthenticated capability endpoint** discloses roadmap | API9 | 1×1 | Only public README content; moves behind auth in P2 | **Accepted (interim)**, expires end of P2 |
| T-API-07 | T | Injection (SQL, command) | API8, A03 | 2×3 | ORM parameterisation, validation, WAF SQLi rules | Planned (P2, P5) |
| T-API-08 | I | SSRF via user-supplied URLs | API7 | 1×3 | No server-side fetch of user URLs; allow-list if ever needed | Planned (P6) |
| T-API-09 | I | Error messages leak stack traces, SQL, paths, secrets | API8 | 2×2 | Generic envelope, no input echo, internal logging | **Mitigated (P1, tested)** |
| T-API-10 | R | Requests untraceable during investigation | — | 2×2 | Correlation IDs, structured logs | **Mitigated (P1)** |
| T-API-11 | T | Log injection / forging | — | 2×2 | JSON logging, control-char neutralisation, ID allow-list | **Mitigated (P1, tested)** |
| T-API-12 | I | Improper inventory: undocumented or debug endpoints | API9 | 2×2 | Docs disabled in deployed envs; inventory from route table | Docs **mitigated (P1)**; inventory P6 |

### TB4 — API → Database

| ID | STRIDE | Threat | L×I | Control(s) | Status |
|---|---|---|---|---|---|
| T-DB-01 | I | Database exposed to the internet | 1×3 | Isolated subnets, `publicly_accessible=false`, SG, Checkov | Local analogue **mitigated (P1)**; AWS P3–4 |
| T-DB-02 | I | Credential theft | 2×3 | Secrets Manager with rotation; never in env files in AWS | Planned (P4) |
| T-DB-03 | E | Over-privileged app DB role | 2×3 | Separate migration and runtime roles | Planned (P2) |
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
| T-SC-01 | T | Vulnerable or malicious dependency | 2×3 | Hash-pinned Python deps, lockfile npm, pip-audit, npm audit, `--ignore-scripts` | **Mitigated (P1)**; SBOM + Trivy P8 |
| T-SEC-01 | I | Secret committed to git | 2×3 | Gitleaks pre-commit + CI (full history), `.gitignore` | **Mitigated (P1)** |
| T-IAC-01 | T | Dev change applied to production | 1×3 | Per-env roots, `allowed_account_ids` (ADR-0014) | Planned (P3) |
| T-IAC-02 | I | Terraform state disclosure | 1×3 | Encrypted, private, versioned state bucket | Planned (P3) |
| T-WAF-01 | T | WAF rule disabled without review | 2×3 | Terraform-only changes, PR approval | Planned (P5) |
| T-WAF-02 | E | Compromised app used to weaken WAF | 1×3 | App holds read-only WAF permissions (ADR-0008) | Planned (P5) |
| T-AUD-01 | R | Audit records altered or deleted | 2×3 | Hash chain, INSERT-only grants, Object Lock (ADR-0005) | Planned (P2, P4) |
| T-CNT-01 | E | Container breakout / privilege escalation | 1×3 | Non-root, read-only FS, `cap_drop: ALL`, no-new-privileges | **Mitigated (P1, local)** |

## 4. Attack paths (top three)

1. **Origin bypass → unfiltered injection.** Attacker finds the origin, sends payloads that WAF
   would block. Broken by ADR-0001 (no public origin) and by app-layer validation and
   parameterisation, which hold even without WAF.
2. **Credential stuffing → session theft → data access.** Broken at the WAF rate rule, app lockout,
   MFA, short-lived tokens, and RBAC/object checks; detectable through failed-login telemetry.
3. **Poisoned log line → AI recommends harmful change → operator applies it.** Broken because AI
   output is schema-bound and advisory, proposals need approval, and real WAF changes need a
   Terraform PR with review.

## 5. Residual risk (Phase 1)

- Single-maintainer project: separation of duties is simulated by role checks, not by
  different people. Documented as accepted for a portfolio.
- No edge protection exists yet; the local stack is bound to 127.0.0.1 and must not be exposed.
- T-API-06 accepted until the end of Phase 2.
