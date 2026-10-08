# Security controls

This is the control catalogue and the requirement → threat → control → implementation → evidence
matrix (spec §37). It is updated every phase. "Evidence" points to something a reviewer can run
or read.

## 1. Defense-in-depth layers (spec §8)

| # | Layer | Why it exists | Control IDs | Status |
|---|---|---|---|---|
| 1 | DNS | Authoritative records managed as code; CAA limits who can issue certificates | C-DNS-01 | P5 |
| 2 | CDN / edge | Terminates TLS close to users, hides origin, absorbs volume | C-EDGE-01..03 | P5 |
| 3 | WAF | Blocks known attack patterns before they cost origin resources | C-WAF-01..04 | P5 |
| 4 | Load balancer | Private origin, HTTPS, desync protection | C-EDGE-02, C-LB-01 | P4 |
| 5 | Security groups | Each tier reachable only from the tier above it | C-NET-02 | P3 |
| 6 | Private networking | App and DB never directly routable from the internet | C-NET-01 | P3 (local analogue P1) |
| 7 | Authentication | Proves identity, resists stuffing and theft | C-ID-01..07 | P2 |
| 8 | API authorization | Stops BOLA/BFLA regardless of UI | C-API-01..02 | P2, P6 |
| 9 | Application validation | Rejects malformed and over-posted input; limits output | C-API-04, C-API-06 | P1 pattern, P2+ |
| 10 | Database security | Least-privilege roles, encryption, parameterisation | C-DB-01..04 | P2–4 |
| 11 | IAM | Least privilege per function, no static keys | C-IAM-01..03 | P3, P11 |
| 12 | Secrets management | Secrets never in code, images, Terraform, or CI config | C-SEC-01..02 | P1 (scan), P4 |
| 13 | Logging | Traceability and forensics | C-LOG-01..03, C-AUD-01..03 | P1 (app), P2 (audit) |
| 14 | Monitoring and detection | Detects abuse and failures; turns signals into incidents | C-MON-01, C-SO-01..09 | **P7 (detection, incidents)**, P4 (alarms) |
| 15 | Vulnerability management | Findings are tracked to closure with SLAs | C-VM-01 | P8 |
| 16 | CI/CD security | Prevents vulnerable or secret-bearing code from shipping | C-CICD-01..04 | P1 (baseline), P8, P11 |
| 17 | AI security | Contains prompt injection and AI agency | C-AI-01..06 | P9 |

## 2. Controls implemented in Phase 1

| ID | Control | Implementation | Evidence |
|---|---|---|---|
| C-WEB-01 | API security headers on every response | `backend/app/core/security_headers.py`, `middleware.py` | `tests/security/test_security_headers.py` (200, 404, 400, 500) |
| C-WEB-02 | SPA security headers, strict CSP (no `unsafe-inline`/`unsafe-eval`) | `frontend/security-headers.conf`, `nginx.conf` | Build output has no inline scripts or styles; `docs/security-headers.md` |
| C-WEB-03 | XSS-prone patterns banned at lint time | `frontend/eslint.config.js` (`dangerouslySetInnerHTML`, `innerHTML`, `eval`, web storage) | `npm run lint` in CI |
| C-API-04 | Unknown fields rejected (mass assignment) | Pydantic `extra="forbid"` pattern | `test_mass_assignment_style_extra_field_rejected` |
| C-API-05 | Same-origin API client; refuses absolute URLs, redirects; validates responses | `frontend/src/lib/api/client.ts` | `client.test.ts` |
| C-API-06 | Secure error handling, no input echo | `backend/app/core/errors.py` | `tests/security/test_error_handling.py` |
| C-API-07 | Host header allow-list, wildcards rejected | `TrustedHostMiddleware`, config validator | `test_trusted_host.py`, `test_config.py` |
| C-API-08 | Interactive API docs disabled when deployed | `Settings._enforce_secure_defaults` | `test_api_docs_forced_off_when_deployed` |
| C-LOG-01 | Structured JSON logs with correlation IDs | `backend/app/core/logging.py`, `correlation.py` | `test_logging.py`, `test_correlation_id.py` |
| C-LOG-02 | Secret redaction and log-injection neutralisation | `redact()` | `test_logging.py` |
| C-LOG-03 | Query strings excluded from access logs | `SecurityMiddleware` | Code review; access log fields |
| C-SEC-01 | Secret scanning (pre-commit + CI, full history) | `.gitleaks.toml`, `.pre-commit-config.yaml`, `ci.yml` | Gitleaks run: no leaks |
| C-SEC-02 | No secrets in repo; generated local credentials | `.env.example` placeholders, `make env` (random, mode 600) | `.gitignore`; Gitleaks |
| C-CICD-01 | SAST: Bandit + Ruff `S` rules | `pyproject.toml`, CI | CI job "backend" |
| C-CICD-02 | SCA: pip-audit (hash-pinned), npm audit | `requirements.txt`, `package-lock.json`, CI | No known vulnerabilities at commit time |
| C-CICD-03 | Least-privilege CI token; SHA-pinned actions; no persisted credentials | `.github/workflows/ci.yml` | Workflow file |
| C-CICD-04 | Coverage floor (90%) on backend | `pytest --cov-fail-under=90` | CI output |
| C-CNT-01 | Hardened containers: non-root, read-only FS, `cap_drop: ALL`, no-new-privileges, multi-stage, health checks | `backend/Dockerfile`, `frontend/Dockerfile`, `docker-compose.yml` | `make verify-hardening` against the running stack; Trivy in P8 |
| C-NET-00 | Local DB on internal-only network; services bound to 127.0.0.1 | `docker-compose.yml` | `make verify-hardening` |
| C-GOV-01 | Provenance register with enforcement tests | `app/core/capabilities.py` | `tests/unit/test_capabilities.py` |
| C-GOV-02 | Security-sensitive paths require code-owner review | `.github/CODEOWNERS`, PR template | Branch protection (configured on GitHub) |
| C-GOV-04 | Security exceptions are recorded, justified, compensated and time-limited | `docs/governance/exceptions.md`; exception IDs in implementing config | EXC-0001, EXC-0002 |

## 2a. Controls implemented in Phase 2

| ID | Control | Implementation | Evidence |
|---|---|---|---|
| C-ID-01 | Argon2id password hashing; deployed minimum cost enforced; rehash on login | `app/security/passwords.py`, config validator | `test_security_primitives.py`, `test_config.py` |
| C-ID-02 | 15-minute JWT, algorithm pinned, all claims required; session checked per request | `app/security/tokens.py`, `app/core/authz.py` | `test_forged_or_invalid_tokens_rejected` (alg none, substitution, wrong key/aud/iss/type, expired) |
| C-ID-03 | Rotating refresh tokens, `__Host-` HttpOnly Secure SameSite=Strict cookie, reuse revokes session | `app/services/auth.py`, `app/api/v1/auth.py` | `test_auth_sessions.py`, `make smoke` |
| C-ID-04 | TOTP MFA (encrypted secrets, no replay, ±1 step), hashed single-use recovery codes; mandatory for ADMIN and SECURITY_ENGINEER | `app/security/mfa.py` | `test_auth_mfa.py` |
| C-ID-05 | Lockout after repeated failures (password and MFA share the counter), uniform errors, constant-work dummy hash | `AuthService.login` | `test_auth_login.py` |
| C-ID-06 | CSRF: Origin allow-list plus custom header on cookie-bearing endpoints | `require_same_origin` | `test_cross_site_requests_rejected` |
| C-ID-07 | Password reset: single-use hashed token in URL fragment, 30-minute expiry, rate-limited, revokes sessions | `request_password_reset`, `reset_password`; SPA strips the fragment | `test_auth_password_reset.py`, `auth-flows.test.tsx` |
| C-ID-08 | No default credentials; forced password change and MFA enrollment gate all other access | `app/cli.py`, `pending_steps` | `test_cli.py`, `test_users_mid_setup_are_held_at_setup` |
| C-ID-09 | Browser session: token in memory only, cross-tab refresh lock | `frontend/src/lib/auth/session.ts` | `session.test.ts`; Chromium check: empty web storage, cookie invisible to JS |
| C-API-01 | Object-level authorization on user records (404, audited) | `UserService.get_user` | `test_users_can_read_only_their_own_record` |
| C-API-02 | Function-level authorization declared on every route and enforced | `require_roles`, `public_endpoint`, `authenticated_setup` | `tests/security/test_authz_matrix.py` (incl. mutation check); [authorization.md](authorization.md) |
| C-DB-01 | Separate migrator and runtime roles; explicit per-table grants; query timeouts | `db/bootstrap-roles.sh`, migrations, ADR-0015 | `test_database_roles.py` (privilege matrix) |
| C-DB-03 | Verified TLS to the database required when deployed | Config validator | `test_deployed_environments_require_verified_database_tls` |
| C-AUD-01 | Hash-chained audit log, concurrency-safe, verifiable | `app/services/audit.py` | `test_audit_log.py` (tamper detection, 8 concurrent writers) |
| C-AUD-02 | Append-only: grants (SELECT/INSERT) and triggers that block even the owner | Migration 0002 | `test_app_role_cannot_alter_audit_history`, `test_trigger_blocks_even_the_table_owner` |
| C-SEC-03 | Secrets scoped per container (API never receives migrator/admin passwords) | `docker-compose.yml` | `docker compose config` review |
| C-CICD-05 | Schema drift gate (`alembic check`) in CI and `make test-backend` | `ci.yml`, `Makefile` | CI job output |
| C-GOV-04 | Security exceptions recorded with justification, compensating control and expiry | `docs/governance/exceptions.md` | EXC-0001, EXC-0002 |

## 2b. Controls implemented in Phase 6

| ID | Control | Implementation | Evidence |
|---|---|---|---|
| C-API-03 | Token-bucket rate limiting per IP (before authentication) and per account (after); 429 with Retry-After; first denial audited; cannot be disabled when deployed | `app/security/rate_limit.py`, `app/core/rate_limiting.py`, ADR-0017 | `test_rate_limiting.py` (incl. 40-thread concurrency), `make smoke` |
| C-API-09 | Endpoint policy registry: risk, rate limit, OWASP exposure for every route; must equal the route table | `app/core/api_policy.py` | `test_registry_matches_the_route_table` |
| C-API-10 | API inventory with live per-endpoint metrics (templates only, no personal data) and computed status | `app/services/api_inventory.py`, `app/core/api_metrics.py` | `test_api_inventory.py` |
| C-API-11 | Route-table sweeps: request bodies forbid unknown fields; JSON routes declare response models; sensitive-looking response fields need approval | — | `test_api_protections.py` |
| C-API-12 | Outbound request (SSRF) guard: HTTPS, allow-list, every resolved address public | `app/security/egress.py` | `test_egress.py` |
| C-NET-03 | Client IP from `X-Forwarded-For` only via trusted proxy networks, chain walked right to left | `app/core/client_ip.py`, pinned edge subnet, nginx overwrite | `test_client_ip.py`, `make smoke` |
| C-GOV-05 | OWASP API Top 10 coverage with cited test evidence that must exist | `app/core/owasp_coverage.py` | `test_owasp_coverage.py` |

## 2c. Controls implemented in Phase 7

| ID | Control | Implementation | Evidence |
|---|---|---|---|
| C-SO-01 | Append-only security events; `incident_id` write-once (trigger) | Migrations 0006 and 0007, `app/models/security_event.py` | `test_app_role_cannot_alter_or_remove_events`, `test_evidence_links_are_write_once` |
| C-SO-02 | Detect-only HTTP analysis: 17 rules, double decoding, bounded input, sensitive snippets redacted, incident free text excluded | `app/security/http_analysis.py`, `app/core/http_inspection.py` | `test_http_analysis.py`, `test_sensitive_query_parameters_are_redacted`, `test_inspection_exclusions_name_real_routes_and_fields` |
| C-SO-03 | ReDoS-safe patterns | Linear-time rules, input bounds | `test_rules_are_linear_on_adversarial_input` |
| C-SO-04 | Synchronous correlation under the audit lock: exactly-once detections, partitioned by provenance (ADR-0018) | `app/services/correlation.py` | `test_concurrent_failures_raise_exactly_one_detection_and_incident` (30 threads), `test_detections_never_cross_provenance` |
| C-SO-05 | Incident workflow and role rules enforced on the server; UI renders `available_moves` and `permissions` | `app/services/incidents.py` | `test_incidents.py` (workflow table, analysts and viewers), `secops.test.tsx` |
| C-SO-06 | Timeline integrity: each entry's SHA-256 committed to the audit chain and verified on read; incidents never deleted | `verify_timeline`, migration 0007 | `test_tampering_with_the_timeline_is_detected`, `test_deleting_a_timeline_entry_is_detected`, `test_app_role_cannot_rewrite_incident_records` |
| C-SO-07 | Optimistic concurrency on incidents and applications (409 `stale_version`) | `version` columns | `test_stale_writes_are_refused`; UI reload prompt in `secops.test.tsx` |
| C-SO-08 | Attack simulator safe by construction: no network I/O, no target input, RFC 5737 addresses, SIMULATED provenance, leads only, audited (ADR-0019) | `app/services/simulator.py` | `test_a_simulation_cannot_be_given_a_target`, `test_every_scenario_produces_only_simulated_activity`, `test_simulations_never_appear_in_the_live_view` |
| C-SO-09 | Attacker-controlled evidence rendered as text only (no markup), under the strict CSP | `EvidenceText`, `ThreatsPage` | `secops.test.tsx`: a `<script>` snippet renders as text; C-WEB-02, C-WEB-03 |
| C-API-01 | Object-level authorization extended to applications (developers see only their own; 404, audited) | `app/services/applications.py` | `test_developers_see_only_their_own_applications` |

## 3. Matrix: requirement → threat → control → implementation → evidence

| Requirement | Threat | Control | Implementation | Evidence | Phase |
|---|---|---|---|---|---|
| SQL injection | T-API-07 | AWS WAF SQLi rules + validation + parameterised queries + detection | `waf` module; Pydantic schemas; SQLAlchemy ORM only; HTTP analysis and COR-003 | Query-param validation tests; `test_sql_injection_in_a_query_parameter_is_recorded`; `make smoke`; WAF logs (P5) | **P2 (app), P7 (detection)**, P5 |
| XSS | T-ID-02, T-EDGE-06 | React escaping + strict CSP + lint bans + WAF XSS rules | `security-headers.conf`; `eslint.config.js`; WAF | Lint in CI; header tests; ZAP (P8) | P1, P5, P8 |
| Credential stuffing | T-ID-01 | WAF rate rule + app limiter + lockout + MFA + detection | WAF module; auth service; `api_policy.LOGIN`; COR-001, COR-007 | `test_account_locks_after_repeated_failures`, `test_login_is_limited_per_ip_with_retry_after`, `test_credential_stuffing_fires_at_threshold_and_not_before`; WAF match counts (P5) | **P2, P6, P7**, P5 |
| Broken object authorization | T-API-01 | Ownership checks in services; probing detected | `UserService.get_user`, `ApplicationService`; COR-004 | `test_users_can_read_only_their_own_record`, `test_developers_see_only_their_own_applications` | **P2, P7** |
| Tampered incident evidence | T-SO-01 | Append-only events, write-once links, timeline digests in the audit chain | ADR-0018 | `test_tampering_with_the_timeline_is_detected`, `test_evidence_links_are_write_once` | **P7** |
| Simulated data mistaken for real | T-SO-02 | Provenance partitioning, separate views, banner | ADR-0009, ADR-0019 | `test_simulations_never_appear_in_the_live_view`, `make smoke` | **P7** |
| Broken function authorization | T-API-02 | Role dependency on every route | `core/authz.py` | `test_authz_matrix.py` | **P2** |
| Mass assignment | T-API-03 | `extra="forbid"` | Request schemas | `test_every_request_body_rejects_unknown_fields` (sweep) | **P1, P6** |
| Excessive data exposure | T-API-05 | Explicit response models | ADR-0012 | `test_every_json_route_declares_a_response_model`, `test_no_response_model_exposes_secret_fields` | **P1, P6** |
| Information leakage in errors | T-API-09 | Generic envelope, internal logging | `errors.py` | `test_error_handling.py` | **P1** |
| Origin bypass | T-EDGE-03 | Internal ALB + VPC origin | `alb`, `cloudfront` modules | External connection test fails; Checkov | P4–5 |
| Public database | T-DB-01 | Isolated subnets, SG, `publicly_accessible=false` | `rds`, `vpc` modules | Checkov; plan review | P3–4 |
| Secret leakage | T-SEC-01 | Gitleaks + Secrets Manager | `.gitleaks.toml`; `secrets-manager` module | Gitleaks report | **P1**, P4 |
| Supply chain | T-SC-01 | Pinned deps + SCA + SBOM + image scan | Lock files; Syft; Trivy | CI artifacts | **P1**, P8 |
| Audit tampering | T-AUD-01 | Hash chain + grants + triggers + Object Lock | ADR-0005 | `test_audit_log.py`, `make verify-audit` | **P2**, P4 |
| Prompt injection | T-AI-01, T-AI-02 | Delimiting, scoring, schema-bound output | `app/ai/guardrails` | Injection corpus tests | P9 |
| Excessive AI agency | T-AI-05 | Proposals + human approval | `ai_action_proposals` | Approval workflow tests; audit | P9 |
| WAF weakened via app | T-WAF-02 | Read-only WAF IAM; Terraform-only changes | ADR-0008; IAM module | IAM policy; Access Analyzer | P5 |
| Certificate expiry | T-EDGE-02 | ACM managed renewal + expiry alerting | ACM module; worker poller | CloudWatch alarm; dashboard | P5 |
| Cross-environment change | T-IAC-01 | Per-env roots, account guards | ADR-0014 | Plan fails on wrong account | P3 |

## 4. Control ID index (planned)

C-DNS-01 CAA + Route 53 as code · C-EDGE-01 TLS policy · C-EDGE-02 private origin · C-EDGE-03
CloudFront headers policy · C-WAF-01 managed rule groups · C-WAF-02 custom rules · C-WAF-03
rate-based rules · C-WAF-04 Terraform-only WAF changes · C-LB-01 ALB desync/invalid-header
protection · C-NET-01 private subnets · C-NET-02 tiered SGs · C-ID-01 Argon2id · C-ID-02
short-lived JWT · C-ID-03 rotating refresh tokens · C-ID-04 MFA · C-ID-05 lockout · C-ID-06 CSRF
defenses · C-ID-07 secure reset · C-API-01 object authz · C-API-02 function authz · C-API-03 app
rate limiting · C-DB-01 least-privilege roles · C-DB-02 encryption · C-DB-03 TLS required ·
C-DB-04 backups · C-IAM-01 per-function roles · C-IAM-02 no static keys · C-IAM-03 permission
documentation · C-AUD-01 hash chain · C-AUD-02 INSERT-only grants · C-AUD-03 Object Lock archive ·
C-MON-01 alarms · C-SO-01..09 security operations (Phase 7, section 2c) · C-VM-01 findings lifecycle · C-AI-01..06 per ADR-0007 · C-GOV-03 change
management.
