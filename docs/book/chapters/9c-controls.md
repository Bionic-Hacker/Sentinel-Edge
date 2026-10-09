# Implemented Controls

Every control below is implemented and has evidence a reviewer can run or read. Planned controls are indexed in `docs/security-controls.md`.

| ID | Control | Evidence |
|---|---|---|
| C-WEB-01 | API security headers on every response, including errors | `test_security_headers.py` (200, 400, 404, 500) |
| C-WEB-02 | SPA strict CSP, no `unsafe-inline` / `unsafe-eval` | No inline code in build output; hardening check |
| C-WEB-03 | XSS-prone patterns banned at lint time | ESLint in CI |
| C-WEB-04 | Cross-origin isolation: COOP `same-origin`, COEP `require-corp` | `make verify-hardening`; ZAP rule 90004 |
| C-API-01 | Object-level authorization (404, audited): users, applications, incidents, findings, scans, SBOMs, threat models, exceptions, change requests | `test_users_can_read_only_their_own_record`, `test_developers_see_only_their_own_applications`, `test_developers_work_only_on_their_own_applications`, `test_developers_see_only_their_own_applications_models` |
| C-API-02 | Function-level authorization on every route | `test_authz_matrix.py` (with mutation check) |
| C-API-03 | Token-bucket rate limiting per IP and per account | `test_rate_limiting.py` (40-thread), `make smoke` |
| C-API-04 | Unknown request fields rejected | `test_every_request_body_rejects_unknown_fields` |
| C-API-05 | Same-origin API client; response validation | `client.test.ts` |
| C-API-06 | Secure error envelope, no input echo | `test_error_handling.py` |
| C-API-07 | Host header allow-list, no wildcards | `test_trusted_host.py`, `test_config.py` |
| C-API-08 | API docs disabled when deployed | `test_api_docs_forced_off_when_deployed` |
| C-API-09 | Endpoint policy registry equals the route table | `test_registry_matches_the_route_table` |
| C-API-10 | API inventory with privacy-preserving metrics | `test_api_inventory.py` |
| C-API-11 | Route-table sweeps (bodies, response models, sensitive fields) | `test_api_protections.py` |
| C-API-12 | Outbound request (SSRF) guard | `test_egress.py` |
| C-API-13 | Backend enumerations and the SPA's validator lists must match | `test_frontend_contract.py` |
| C-ID-01 | Argon2id; deployed minimum enforced; rehash on login | `test_security_primitives.py` |
| C-ID-02 | 15-min JWT, algorithm pinned, session checked per request | `test_forged_or_invalid_tokens_rejected` |
| C-ID-03 | Rotating refresh tokens in `__Host-` cookie; reuse revokes | `test_auth_sessions.py` |
| C-ID-04 | TOTP MFA (encrypted, no replay); hashed recovery codes | `test_auth_mfa.py` |
| C-ID-05 | Lockout, uniform errors, constant-work dummy hash | `test_auth_login.py` |
| C-ID-06 | CSRF: Origin allow-list plus custom header | `test_cross_site_requests_rejected` |
| C-ID-07 | Single-use, hashed reset token in URL fragment | `test_auth_password_reset.py` |
| C-ID-08 | No default credentials; forced setup gate | `test_cli.py`, `test_users_mid_setup_are_held_at_setup` |
| C-ID-09 | Browser token in memory; cross-tab refresh lock | `session.test.ts`; Chromium check |
| C-DB-01 | Separate migrator and runtime roles; explicit grants | `test_database_roles.py` |
| C-DB-03 | Verified database TLS required when deployed | `test_deployed_environments_require_verified_database_tls` |
| C-AUD-01 | Hash-chained, concurrency-safe, verifiable audit log | `test_audit_log.py`, `make verify-audit` |
| C-AUD-02 | Append-only by grants and owner-proof triggers | `test_trigger_blocks_even_the_table_owner` |
| C-LOG-01..03 | JSON logs, correlation IDs, redaction, no query strings | `test_logging.py`, `test_correlation_id.py` |
| C-NET-00 | Database on internal network; services bound to localhost | `make verify-hardening` |
| C-NET-03 | Client IP only via trusted proxy networks | `test_client_ip.py`, `make smoke` |
| C-CNT-01 | Non-root, read-only, no capabilities, no-new-privileges | `make verify-hardening` |
| C-SEC-01..03 | Secret scanning; generated secrets; per-container scoping | Gitleaks; compose review |
| C-CICD-01..05 | SAST, SCA, least-privilege CI, coverage floor, schema drift gate | CI jobs |
| C-CICD-06 | One scan pipeline (SAST, SCA, secrets, IaC, containers, SBOM, DAST), locally and in CI | `make scan`, CI job `security-scans` |
| C-CICD-07 | SentinelEdge Semgrep rules with annotated tests | `make scan-test` |
| C-CICD-08 | Scan gate: fixable critical/high blocks unless accepted; fails closed | `test_scanning.py` |
| C-CICD-09 | Contained scanners: digest-pinned, read-only repository, no Docker socket | `make image-digests` |
| C-CICD-10 | OS security fixes applied at image build | Trivy image reports |
| C-CICD-11 | Authenticated DAST as a read-only viewer with a one-scan session | `test_dast_scanner_session_is_read_only_and_revocable` |
| C-GOV-01 | Provenance register with enforcement tests | `test_capabilities.py` |
| C-GOV-02 | Code-owner review on sensitive paths | CODEOWNERS, branch protection |
| C-GOV-03 | Change management: rollback and validation plans, an approver other than the requester, implemented then validated or rolled back | `test_a_change_goes_from_request_to_validation`, `test_a_waf_change_drives_the_simulated_waf_and_rolls_back` |
| C-GOV-04 | Exceptions with justification, compensation and an expiry within the risk's limit; separation of duties; held in the app | `test_whoever_asks_cannot_approve`, `test_an_approved_exception_expires_on_its_date` |
| C-GOV-05 | OWASP API coverage with evidence that must exist | `test_owasp_coverage.py` |
| C-GOV-06 | Threat model and controls as code, checked against the documents; cited evidence must exist | `test_the_shipped_catalogue_is_exactly_what_the_documents_produce`, `test_every_cited_piece_of_evidence_exists` |
| C-GOV-07 | Application threat models: real controls cited, elements retired, archive and delete by role, audited | `test_threats_must_cite_real_controls_and_boundaries`, `test_a_lead_deletes_an_application_model_and_the_audit_log_keeps_it` |
| C-GOV-08 | Governance decisions final (triggers); nothing deletable by the app role | `test_the_database_refuses_self_approval_and_rewritten_decisions` |
| C-GOV-09 | The scan gate's accepted risks generated from approved exceptions | `test_approved_scan_finding_exceptions_become_the_gate_register` |
| C-GOV-10 | Explainable posture score: coverage minus named signals, method published | `test_the_method_is_published_with_the_score`, `test_live_signals_deduct_points_and_name_their_records` |
| C-SO-01 | Append-only security events; write-once incident links | `test_app_role_cannot_alter_or_remove_events`, `test_evidence_links_are_write_once` |
| C-SO-02 | Detect-only HTTP analysis, redaction, inspection exclusions | `test_http_analysis.py`, `test_inspection_exclusions_name_real_routes_and_fields` |
| C-SO-03 | ReDoS-safe detection patterns | `test_rules_are_linear_on_adversarial_input` |
| C-SO-04 | Exactly-once correlation under the audit lock, partitioned by provenance | `test_concurrent_failures_raise_exactly_one_detection_and_incident` (30-thread) |
| C-SO-05 | Incident workflow and role rules on the server | `test_incidents.py`, `secops.test.tsx` |
| C-SO-06 | Timeline digests in the audit chain, verified on read | `test_tampering_with_the_timeline_is_detected` |
| C-SO-07 | Optimistic concurrency (409 `stale_version`) | `test_stale_writes_are_refused` |
| C-SO-08 | Simulator safe by construction (no target, SIMULATED only) | `test_a_simulation_cannot_be_given_a_target`, `test_simulations_never_appear_in_the_live_view` |
| C-SO-09 | Attacker data rendered as text only | `secops.test.tsx` (`<script>` snippet) |
| C-VM-01 | Findings de-duplicated, fixed only by a covering scan, reopened on return | `test_vulnerabilities.py` |
| C-VM-02 | Remediation SLA from detection; past-SLA on the dashboard | `test_severity_change_keeps_the_original_sla_clock` |
| C-VM-03 | Risk acceptance: leads only, bounded expiry, immutable decision, expiry reopens | `test_risk_acceptance_lifecycle`, `test_an_expired_acceptance_reopens_its_finding` |
| C-VM-04 | Imports validated, bounded, all-or-nothing; CLI only | `test_import_is_all_or_nothing` |
| C-VM-05 | New critical/high findings become events; fixable criticals open incidents | `test_events_per_import_are_bounded` |
| C-VM-06 | SBOMs per scan and artifact with SHA-256; CycloneDX download | `test_scans_and_sboms` |
