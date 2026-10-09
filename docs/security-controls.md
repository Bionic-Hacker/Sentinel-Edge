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
| 15 | Vulnerability management | Findings are tracked to closure with SLAs | C-VM-01..06 | P8 |
| 16 | CI/CD security | Prevents vulnerable or secret-bearing code from shipping | C-CICD-01..04 | P1 (baseline), P8, P11 |
| 17 | AI security | Contains prompt injection and AI agency | C-AI-01..07 | **P9** |
| 18 | Governance | Risk is modelled, accepted and changed on the record, by someone other than whoever asked | C-GOV-01..10 | P1, **P10** |

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

## 2d. Controls implemented in Phase 8

| ID | Control | Implementation | Evidence |
|---|---|---|---|
| C-CICD-06 | SAST, SCA, secrets, IaC, container scanning, SBOMs and DAST in one pipeline, locally and in CI (ADR-0020) | `scripts/scan.sh`, `make scan`, `make dast`, CI job `security-scans` | CI artifact `security-scans-<run>`; `make scan` output |
| C-CICD-07 | SentinelEdge Semgrep rules encode the project's own rules, each with annotated tests | `scanning/semgrep/` | `make scan-test` (CI job `semgrep-rules`) |
| C-CICD-08 | Scan gate: fixable critical/high blocks unless an unexpired accepted risk covers it; awaiting-fix package vulnerabilities reported; fails closed on missing or unreadable reports | `app/scanning/gate.py`, `scanning/accepted-findings.toml` | `test_scanning.py` (gate, expiry, `--expect`, coverage) |
| C-CICD-09 | Contained scanners: images pinned by tag and digest, read-only repository, no Docker socket, offline Checkov; stale pins reported | `scripts/scan.sh`, `scripts/image-digests.sh` | `make image-digests` |
| C-CICD-10 | OS security fixes applied at image build on top of the pinned base | `backend/Dockerfile`, `frontend/Dockerfile` | Trivy image reports (CVE-2026-4775 fixed) |
| C-CICD-11 | Authenticated DAST as a read-only VIEWER with a one-scan session, revoked afterwards; logout excluded; local stack only | `app/cli.py` (`dast-session`, `openapi --server`), `scripts/scan.sh dast` | `test_dast_scanner_session_is_read_only_and_revocable`, `test_openapi_document_lists_every_endpoint` |
| C-VM-01 | Findings lifecycle: de-duplicated by fingerprint, fixed only by a scan that covers the finding, reopened on return, never fixed by hand | `app/services/vulnerabilities.py`, `app/scanning/findings.py` | `test_vulnerabilities.py` (import, fixed and reopened, partial scans) |
| C-VM-02 | Remediation SLA from detection (critical 7, high 30, medium 90, low 180 days); past-SLA counted on the dashboard | `SLA`, overview | `test_import_deduplicates_and_records_the_scan`, `test_severity_change_keeps_the_original_sla_clock` |
| C-VM-03 | Risk acceptance: leads only, justification, compensating control, expiry within the severity limit, immutable decision, one in force, expiry reopens | Migration 0009 (column grants, partial unique index), `accept_risk` | `test_risk_acceptance_lifecycle`, `test_an_expired_acceptance_reopens_its_finding`, `test_the_app_role_cannot_rewrite_the_record` |
| C-VM-04 | Imports validated and bounded, all-or-nothing, insert-only scan runs; CLI only | `app/schemas/vulnerabilities.py`, `import-scan` | `test_import_is_all_or_nothing`, `test_scanner_text_is_bounded_and_control_characters_replaced`, `test_cli_import` |
| C-VM-05 | New and reopened critical/high findings become security events (bounded); fixable criticals open incidents | `_report_events` | `test_new_critical_findings_are_security_events_and_fixable_ones_open_an_incident`, `test_events_per_import_are_bounded` |
| C-VM-06 | SBOMs stored per scan and artifact with SHA-256; components searchable; CycloneDX download as an attachment | `Sbom`, `/api/v1/sboms` | `test_scans_and_sboms`, `appsec.test.tsx` |
| C-API-01 | Object-level authorization extended to findings, scans and SBOMs (developers: own applications; 404, audited) | `VulnerabilityService` | `test_developers_work_only_on_their_own_applications` |
| C-API-13 | Backend enumerations and the SPA's validator lists must match | `tests/unit/test_frontend_contract.py` | CI |
| C-WEB-04 | Cross-origin isolation: COOP `same-origin` and COEP `require-corp` on the SPA and the API | `security-headers.conf`, `security_headers.py` | `make verify-hardening`; ZAP rule 90004 |

## 2e. Controls implemented in Phase 10

| ID | Control | Implementation | Evidence |
|---|---|---|---|
| C-GOV-03 | Change management: a security-sensitive change needs a rollback plan and a validation plan, an approver other than the requester (service and database CHECK), an implementation reference, then validation or rollback; a `waf_rule` change drives the simulated WAF (ADR-0023) | `app/services/risk_governance.py`, migration 0011 | `test_a_change_goes_from_request_to_validation`, `test_a_waf_change_drives_the_simulated_waf_and_rolls_back`, `test_whoever_asks_cannot_approve` |
| C-GOV-04 | Security exceptions held in the application: separation of duties, expiry no later than the risk allows (critical 30, high 90, medium 180, low 365 days), expiry on the date without a scheduler, reasons for rejection, withdrawal and closure; EXC-0001 and EXC-0002 migrated, not retyped | `SecurityException`, migration 0011 | `test_whoever_asks_cannot_approve`, `test_an_approved_exception_expires_on_its_date`, `test_rejection_withdrawal_and_closure_need_reasons`, `test_migration_imports_the_documented_exceptions` |
| C-GOV-06 | Threat model and control catalogue maintained as code: generated from the reviewed documents, shipped with the API, refused by a test if they differ; cited evidence must exist; SentinelEdge's own model is read-only in the application (ADR-0022) | `app/governance/catalogue_source.py`, `make governance-catalogue` | `test_the_shipped_catalogue_is_exactly_what_the_documents_produce`, `test_every_cited_piece_of_evidence_exists`, `test_sentineledge_s_own_model_is_maintained_as_code` |
| C-GOV-07 | Application threat models: threats cite real controls and boundaries; elements are retired, never deleted; models archived (leads, developers on their own applications) or deleted (leads only), each audited, a deletion with a summary of what it removed | `app/services/governance.py`, migration 0013 | `test_threats_must_cite_real_controls_and_boundaries`, `test_elements_are_retired_not_deleted`, `test_a_lead_deletes_an_application_model_and_the_audit_log_keeps_it`, `test_analysts_and_viewers_cannot_archive` |
| C-GOV-08 | Governance decisions are final: database triggers refuse a rewritten decision or a revived request; the app role cannot delete exceptions or change requests; each record's history is read from the hash-chained audit log | Migration 0011 | `test_the_database_refuses_self_approval_and_rewritten_decisions`, `test_a_cancelled_change_cannot_be_revived_or_rewritten`, `test_the_app_role_cannot_delete_governance_decisions` |
| C-GOV-09 | The scan gate's accepted-risk register is generated from approved scan-finding exceptions: the application is the system of record | `accepted_risks_toml`, `make accepted-risks` | `test_approved_scan_finding_exceptions_become_the_gate_register` |
| C-GOV-10 | Explainable posture score: coverage minus live signals, each factor naming its records; every control family in exactly one category; the method returned with the score; daily snapshots | `app/services/posture.py`, migration 0012 | `test_every_control_family_belongs_to_exactly_one_category`, `test_the_method_is_published_with_the_score`, `test_live_signals_deduct_points_and_name_their_records`, `test_leads_take_snapshots_and_the_trend_records_them` |
| C-API-01 | Object-level authorization extended to threat models, exceptions and change requests (developers: own applications; 404, audited) | `GovernanceService`, `RiskGovernanceService` | `test_developers_see_only_their_own_applications_models`, `test_developers_raise_requests_only_for_their_own_applications` |
| C-API-13 | Governance enumerations and PASTA stages match the SPA's validator lists | `tests/unit/test_frontend_contract.py` | `governance.test.tsx` |

## 2f. Controls implemented in Phase 9

| ID | Control | Implementation | Evidence |
|---|---|---|---|
| C-AI-01 | Untrusted data delimited as JSON under a per-call nonce, never concatenated into instructions; an allow-list of fields per subject; prompt-risk scoring with named signals; invisible and bidirectional characters removed (ADR-0007, ADR-0024) | `app/ai/guardrails.py` | `test_injection_corpus_scores_high`, `test_untrusted_data_cannot_close_its_delimiter`, `test_invisible_characters_are_removed_and_flagged`, `test_injection_cannot_change_the_offline_verdict` |
| C-AI-02 | Output contract: one strict JSON object; every observed-evidence item a verbatim quote of a field that was sent; inference kept apart; known controls only; anything else rejected, never repaired | `app/ai/contract.py` | `test_evidence_must_quote_the_input_verbatim`, `test_hostile_answers_are_rejected_not_repaired`, `test_malformed_answers_are_rejected`, `test_a_compromised_model_cannot_act_or_lie_about_evidence` |
| C-AI-03 | AI text and quoted attacker data rendered as text only; never executed or used to build queries; the SPA validates every AI response | `features/ai/`, `lib/api/aiValidators.ts` | `ai.test.tsx` |
| C-AI-04 | Minimisation before data reaches a model: allow-listed, bounded fields; addresses and e-mails pseudonymised; only Amazon Bedrock, which does not train on inputs | `app/ai/guardrails.py`, `app/services/ai.py` | `test_addresses_and_emails_are_pseudonymised`, `test_fields_and_the_whole_input_are_bounded` |
| C-AI-05 | No AI agency: three proposal types, tighten-only (a WAF rule to block, never weaker); a lead approves and the action runs as that person through its own workflow, in one transaction; decisions final (trigger); high prompt-risk needs a written reason | `app/services/ai.py`, migration 0014 | `test_a_lead_approves_proposals_and_the_actions_run`, `test_an_action_that_no_longer_applies_is_refused_and_nothing_changes`, `test_the_record_cannot_be_rewritten` |
| C-AI-06 | Cost bounds checked before any call: analyses per user per day, platform tokens per day, tokens per answer; viewers (the DAST scanner) cannot run analyses; every call audited with model, usage and prompt risk | `app/services/ai.py`, `app/core/config.py` | `test_quotas_are_checked_before_the_call`, `test_who_may_analyse_what` |
| C-AI-07 | Bedrock least privilege: one `bedrock:InvokeModel` permission on one model; short-lived session credentials locally, the task role when deployed; AWS error text never shown or stored; answers cut at the token limit are failures | `app/ai/bedrock.py`, `scripts/bedrock-credentials.sh`, `docs/bedrock-setup.md` | `test_aws_errors_become_our_own_words`, `test_an_answer_cut_off_at_the_token_limit_is_a_failure`, `test_model_ids_cannot_be_urls_or_paths` |
| C-API-01 | Object-level authorization extended to AI analyses and proposals (developers: their own applications' findings and threat models only; 404, audited) | `AiService` | `test_who_may_analyse_what` |
| C-API-13 | AI enumerations match the SPA's validator lists | `tests/unit/test_frontend_contract.py` | `ai.test.tsx` |

## 3. Matrix: requirement → threat → control → implementation → evidence

| Requirement | Threat | Control | Implementation | Evidence | Phase |
|---|---|---|---|---|---|
| SQL injection | T-API-07 | AWS WAF SQLi rules + validation + parameterised queries + detection | `waf` module; Pydantic schemas; SQLAlchemy ORM only; HTTP analysis and COR-003 | Query-param validation tests; `test_sql_injection_in_a_query_parameter_is_recorded`; `make smoke`; WAF logs (P5) | **P2 (app), P7 (detection)**, P5 |
| XSS | T-ID-02, T-EDGE-06 | React escaping + strict CSP + lint bans + Semgrep rules + WAF XSS rules | `security-headers.conf`; `eslint.config.js`; `scanning/semgrep/frontend.yml`; WAF | Lint in CI; header tests; ZAP active XSS rules passed (SCAN-0003) | **P1, P8**, P5 |
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
| Supply chain | T-SC-01 | Pinned deps + SCA + SBOM + image scan + build-time OS fixes | Lock files; Syft; Trivy; Dockerfiles | CI artifact `security-scans-<run>`; Vulnerabilities and SBOM pages | **P1, P8** |
| Known vulnerabilities shipped | T-VM-03, T-VM-04 | Scan gate, findings lifecycle, SLA, risk acceptance | ADR-0020, ADR-0021 | `test_scanning.py`, `test_vulnerabilities.py`; [runbook](runbooks/vulnerability-remediation.md) | **P8** |
| Risk accepted or changed without oversight | T-GOV-01, T-GOV-02, T-GOV-03 | Separation of duties, expiry, immutable decisions, audited history | ADR-0023 | `test_whoever_asks_cannot_approve`, `test_the_database_refuses_self_approval_and_rewritten_decisions`, `test_an_approved_exception_expires_on_its_date` | **P10** |
| Threat model and controls drift from what is built | T-GOV-04, T-GOV-05 | Catalogue as code with a drift test; evidence must exist; explainable score | ADR-0022 | `test_the_shipped_catalogue_is_exactly_what_the_documents_produce`, `test_every_cited_piece_of_evidence_exists`, `test_the_method_is_published_with_the_score` | **P10** |
| Audit tampering | T-AUD-01 | Hash chain + grants + triggers + Object Lock | ADR-0005 | `test_audit_log.py`, `make verify-audit` | **P2**, P4 |
| Prompt injection | T-AI-01, T-AI-02 | Delimiting, scoring, verbatim-evidence contract | ADR-0007, ADR-0024 | `test_injection_corpus_scores_high`, `test_a_compromised_model_cannot_act_or_lie_about_evidence` | **P9** |
| Excessive AI agency | T-AI-05 | Tighten-only proposals + lead approval | `app/services/ai.py` | `test_a_lead_approves_proposals_and_the_actions_run`, `test_the_record_cannot_be_rewritten` | **P9** |
| WAF weakened via app | T-WAF-02 | Read-only WAF IAM; Terraform-only changes | ADR-0008; IAM module | IAM policy; Access Analyzer | P5 |
| Certificate expiry | T-EDGE-02 | ACM managed renewal + expiry alerting | ACM module; worker poller | CloudWatch alarm; dashboard | P5 |
| Cross-environment change | T-IAC-01 | Per-env roots, account guards | ADR-0014 | Plan fails on wrong account | P3 |

## 4. Planned controls

Every control ID used in the threat model and not yet implemented, with the phase that
implements it. When a phase implements one, its row moves to that phase's section above.

| ID | Control | Phase |
|---|---|---|
| C-DNS-01 | CAA records and Route 53 managed as code | 5 |
| C-EDGE-01 | CloudFront TLS policy `TLSv1.2_2021` and HSTS at the edge | 5 |
| C-EDGE-02 | Private origin: CloudFront VPC origin to an internal ALB over HTTPS (ADR-0001) | 4 |
| C-EDGE-03 | CloudFront response headers policy | 5 |
| C-WAF-01 | AWS managed rule groups (core, known bad inputs, SQL injection) | 5 |
| C-WAF-02 | Custom WAF rules for SentinelEdge's own endpoints | 5 |
| C-WAF-03 | Rate-based WAF rules | 5 |
| C-WAF-04 | WAF changes only through reviewed Terraform; the app has read-only WAF access (ADR-0008) | 5 |
| C-LB-01 | ALB desync mitigation (strictest) and invalid-header dropping | 4 |
| C-NET-01 | Private subnets for the application and the database | 3 |
| C-NET-02 | Tiered security groups: each tier reachable only from the tier above | 3 |
| C-IAC-01 | Per-environment Terraform roots with `allowed_account_ids` guards (ADR-0014) | 3 |
| C-IAC-02 | Encrypted, private, versioned Terraform state bucket | 3 |
| C-DB-02 | Encryption at rest (KMS) and in transit (`rds.force_ssl`) | 4 |
| C-DB-04 | Automated database backups | 4 |
| C-IAM-01 | One IAM role per function, least privilege | 3 |
| C-IAM-02 | No static cloud keys: GitHub OIDC for CI (ADR-0010) | 11 |
| C-IAM-03 | Every IAM permission documented with its reason | 3 |
| C-AUD-03 | Audit archive with S3 Object Lock anchoring the chain head | 4 |
| C-MON-01 | CloudWatch alarms for errors, latency and security signals | 4 |
