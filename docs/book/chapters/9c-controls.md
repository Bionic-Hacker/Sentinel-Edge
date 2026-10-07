# Implemented Controls

Every control below is implemented and has evidence a reviewer can run or read. Planned controls are indexed in `docs/security-controls.md`.

| ID | Control | Evidence |
|---|---|---|
| C-WEB-01 | API security headers on every response, including errors | `test_security_headers.py` (200, 400, 404, 500) |
| C-WEB-02 | SPA strict CSP, no `unsafe-inline` / `unsafe-eval` | No inline code in build output; hardening check |
| C-WEB-03 | XSS-prone patterns banned at lint time | ESLint in CI |
| C-API-01 | Object-level authorization (404, audited) | `test_users_can_read_only_their_own_record` |
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
| C-GOV-01 | Provenance register with enforcement tests | `test_capabilities.py` |
| C-GOV-02 | Code-owner review on sensitive paths | CODEOWNERS, branch protection |
| C-GOV-04 | Exceptions with justification, compensation and expiry | EXC-0001, EXC-0002 |
| C-GOV-05 | OWASP API coverage with evidence that must exist | `test_owasp_coverage.py` |
