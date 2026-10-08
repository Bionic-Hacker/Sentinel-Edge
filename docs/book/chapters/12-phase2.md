# Phase 2 — Secure Application Foundation

<p class="lead">Phase 2 built the parts every security platform depends on: who you are, what you may do, and an unalterable record of what you did. It was delivered in eight milestones and released as v0.2.0.</p>

## Milestones

| Milestone | Delivered |
|---|---|
| M0 | Dependency hygiene; `make verify-hardening` |
| M1 | Database foundation with least-privilege roles |
| M2 | Tamper-evident audit log and authentication |
| M3 | RBAC, user management and the audit log API |
| M4 | Frontend: sign-in, setup, user administration, audit viewer |
| M5 | Documentation, end-to-end smoke test, v0.2.0 release notes |
| M6 | Permanent user deletion behind a confirmation dialog (owner request) |
| M7 | Fix for the database-port hardening check on Docker Compose v5 |

## Database least privilege (ADR-0015)

If the API connected as the schema owner, any SQL injection or code-execution bug would inherit the ability to drop tables, rewrite the audit log, or grant itself anything. Phase 2 therefore uses three identities, each with one job:

| Identity | Can | Cannot | Used by |
|---|---|---|---|
| Admin (`POSTGRES_USER`; RDS master) | Create roles and the schema | — | `db/bootstrap-roles.sh`, once |
| `sentinel_migrator` | Own and change the `sentinel` schema | Create roles or databases; superuser; bypass RLS | One-shot `migrate` container |
| `sentinel_app` | Exactly the per-table privileges migrations grant | Any DDL; read `alembic_version`; create in `public` | The API |

- **One bootstrap script everywhere.** The same script runs at first start of the local container, in CI, against a throwaway test database, and (Phase 4) against RDS, so the privilege model cannot drift between environments.
- **Explicit grants, no default privileges.** Each migration that creates a table grants the app role only what that table needs. `ALTER DEFAULT PRIVILEGES` is deliberately avoided, because it would hand every future table full access by accident.
- **A privilege-matrix test** compares the app role's actual grants with a hand-written expected table. Over-granting fails CI.
- **Secrets scoped per container.** The API never receives the migrator or admin password. The migrate container never receives the app password.
- **Resource limits** on the app role: `statement_timeout = 15s`, `idle_in_transaction_session_timeout = 30s`.
- **Verified TLS required when deployed** (`sslmode` `verify-ca` or `verify-full`). Configuration validation refuses to start otherwise.

## Authentication (ADR-0003)

{{figure:auth|Sign-in, MFA, session and refresh rotation. Red nodes are the defensive outcomes.|86}}

### Passwords
Passwords are hashed with **Argon2id** (64 MiB, 3 iterations, parallelism 4 by default). Configuration refuses to deploy below the OWASP minimum, and hashes are upgraded on the next sign-in if parameters rise. Unknown accounts are checked against a dummy hash, so a response takes the same work whether the account exists, is locked or is inactive. Every failure returns the same uniform 401.

### Tokens and sessions
- The **access token** is a signed JWT with a 15-minute lifetime and the algorithm pinned server-side. `aud`, `iss`, `exp` and token type are all required. The SPA holds it in memory only.
- The **refresh token** is an opaque random value in a `__Host-` cookie: `HttpOnly; Secure; SameSite=Strict; Path=/`, with no `Domain`. The `__Host-` prefix guarantees no subdomain can set or overwrite it. The server stores only its hash.
- Refresh tokens **rotate on every use** within a family. Presenting an already-rotated token means it was stolen and replayed, so the whole session is revoked and the event is audited as `auth.refresh_token_reuse`.
- **Revocation is immediate.** Every access token carries its session ID, and each request loads that session, so logout, password change, role change and deactivation take effect at once rather than when the token expires. The role is read from the database on every request.

### Multi-factor authentication
TOTP secrets are Fernet-encrypted with a key held outside the database, so a database dump does not yield working second factors. The last accepted time-step is stored, so a code works exactly once (no replay within its 30-second window). Recovery codes are hashed and single-use. MFA is mandatory for ADMIN and SECURITY_ENGINEER. The setup QR code is rendered locally in the browser, so the secret never goes to a third-party QR service.

### Lockout, CSRF and recovery
- Five failures lock an account for 15 minutes. Password and MFA failures share the counter, and attempts are counted under a `SELECT … FOR UPDATE`, so concurrent guesses are not lost.
- Cookie-bearing endpoints (sign-in, MFA verify, refresh, password reset) require an allowed `Origin` *and* a custom `X-SentinelEdge-CSRF` header. Browsers will not attach a custom header cross-site without a CORS preflight, and the API grants none.
- Password reset uses a single-use, hashed, 30-minute token carried in the URL **fragment**, which is never sent to servers or logged. The SPA strips it from the address bar, and a successful reset revokes all sessions.

### No default credentials
The first admin is created by `make create-admin`, which prints a one-time password, shown once. Everyone else is **invited** by a one-time link (72-hour expiry) delivered through a local outbox. Admins never see or set anyone's password. A new or reset account is held at a setup gate: until the password is changed (and, for privileged roles, MFA enrolled), only `/auth/me`, `/auth/logout`, `/auth/password/change` and the enrollment endpoints respond.

## Authorization

Five roles: ADMIN, SECURITY_ENGINEER, DEVELOPER, ANALYST and VIEWER. Every route depends on exactly one of three guards: `public_endpoint`, `authenticated_setup` or `require_roles(...)`. A route with none fails the test suite.

`tests/security/test_authz_matrix.py` holds the full endpoint-by-role matrix (Appendix D) as an independent, hand-written table. It calls every protected route anonymously (expecting 401) and as every role (expecting 403 exactly where the table says no). A deliberate mutation, weakening one route, fails three tests. That proves the sweep catches drift.

Object-level authorization (OWASP API1) lives in the service layer. Non-admins may read only their own user record. Any other ID returns the *same* 404 as a non-existent one, so existence is not leaked, and the attempt is audited as `authz.denied`. Admins cannot demote, deactivate, delete or reset MFA on themselves, and the last active admin cannot be removed.

### Deactivate versus delete
Deactivation is reversible, revokes sessions at once, and keeps the account for investigation; it is the preferred response during an incident. Deletion (the trash icon, behind a warning dialog whose default action is Cancel) removes the account, sessions and pending links permanently. **Audit history is unaffected**, because audit records hold the actor's ID and email as plain values rather than foreign keys, so the hash chain never changes.

## Tamper-evident audit log (ADR-0005)

{{figure:chain|The audit hash chain. Altering any record breaks every hash after it. Each hash covers the record and the previous hash.|90}}

Every record carries the actor, timestamp, action, resource, result, source IP and correlation ID. Its hash covers the previous record's hash:

```python
def compute_record_hash(prev_hash: str, payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(f"{prev_hash}\n{canonical}".encode()).hexdigest()
```

Four layers protect it:

1. **Hash chain.** Verification walks the chain and reports the first broken record. It is available as `make verify-audit`, `GET /api/v1/audit-logs/verify` (itself audited) and a "Verify integrity" button in the UI.
2. **Grants.** The app role has only `SELECT` and `INSERT` on `audit_log`.
3. **Triggers.** `UPDATE`, `DELETE` and `TRUNCATE` raise an error for *every* role, including the table owner. Getting around that requires `ALTER TABLE … DISABLE TRIGGER`, which is DDL.
4. **Off-host anchor** (Phase 4). The chain head is exported to S3 Object Lock, which closes the one gap a chain cannot close: silent deletion of the newest records.

Writers take `pg_advisory_xact_lock` before reading the chain head, so concurrent requests extend the chain one at a time (tested with eight concurrent writers). Details are redacted and size-bounded *before* hashing, so a secret never enters the chain.

## Frontend

The Phase 2 UI provides sign-in with MFA, a forced setup flow with local QR rendering, password reset, user administration (invite, change role, deactivate, reset 2FA, delete), and an audit-log viewer with filters and integrity verification. The UI hides what a role cannot use, for usability. That is never the control.

One subtle problem had to be solved. Two open tabs refreshing at the same moment would present the same refresh token twice and trip reuse detection, logging the user out (T-ID-06). Refresh is therefore single-flight within a tab and serialized across tabs with the **Web Locks API**.

:::lesson Two real bugs, found by the tests
**Unicode digits.** The MFA check used `\d`, which in Python matches non-ASCII digits such as Arabic-Indic numerals. Those passed validation and then crashed the constant-time comparison with a 500. The fix is ASCII-only `[0-9]`, with a regression test (T-INP-01).
**Role identity.** Roles loaded from the database were plain strings, so an `is` comparison against the enum never matched. That kind of check can silently fail open or closed. The fix is an enum-typed column and `==` comparisons, caught by the authorization sweep (T-AZ-01).
:::

:::evidence Verified in Phase 2
302 backend tests (99% coverage) against real PostgreSQL, and 41 frontend tests. `make smoke`: 26 end-to-end checks against the running stack. In headless Chromium, the full first-run journey left web storage empty, the refresh cookie was invisible to JavaScript, and there were no console errors.
:::
