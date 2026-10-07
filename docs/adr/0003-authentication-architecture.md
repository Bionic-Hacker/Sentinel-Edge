# ADR-0003: Authentication and session architecture

- **Status:** Accepted — implemented in Phase 2 (see addendum)
- **Date:** 2026-10-06
- **Phase:** 2

## Context
The platform holds security telemetry and controls workflows (incident handling, exception
approval) that attackers would value. Sessions must resist token theft, replay, CSRF, and XSS.

## Decision
- Passwords hashed with **Argon2id** (memory-hard). No plaintext or reversible storage.
- **Access token:** signed JWT, 15-minute lifetime, held **in memory only** in the SPA. Signing key
  in Secrets Manager (Phase 4), `alg` pinned server-side, `aud`/`iss`/`exp` validated.
- **Refresh token:** opaque random value in an `HttpOnly; Secure; SameSite=Strict; Path=/api/v1/auth`
  cookie. Stored server-side as a hash. **Rotated on every use**, grouped in families; reuse of
  a rotated token revokes the whole family (theft detection).
- **CSRF:** the refresh endpoint additionally requires a matching `Origin` header and a custom
  request header; state-changing endpoints use bearer tokens, which browsers do not attach
  automatically.
- **MFA:** TOTP, secrets encrypted at rest, with recovery codes. Required for ADMIN and
  SECURITY_ENGINEER.
- **Lockout:** progressive delay and temporary lockout per account, plus per-IP limits, with
  generic error messages that do not reveal whether an account exists.
- **Password reset:** single-use, hashed, short-lived tokens; all sessions revoked on reset.

## Security impact
Addresses T-ID-01..05 (credential stuffing, token theft, session fixation, CSRF, enumeration).
Controls C-ID-01..07.

## Alternatives considered
- Amazon Cognito: strong option for production; rejected because building auth demonstrates the
  engineering the target roles assess. Documented as a production recommendation.
- Tokens in `localStorage`: rejected (XSS-exfiltratable); banned by ESLint rule in Phase 1.

## Consequences
Page reload requires a silent refresh call. Server-side refresh-token storage is required.

## Addendum: as implemented (Phase 2)

Implemented as decided, with these refinements:

- **Refresh cookie path is `/`, not `/api/v1/auth`.** The cookie uses the `__Host-` prefix, which
  browsers only accept with `Path=/`, `Secure` and no `Domain`. The prefix guarantees the cookie
  can't be set or overwritten by a subdomain, which is worth more than narrowing its path. The API
  reads it on the refresh endpoint only.
- **Session revocation is immediate.** Every access token carries its session ID; each request
  loads the session, so logout, password change, role change and deactivation take effect at once,
  not when the 15-minute token expires. The role is read from the database on every request.
- **Forced setup.** A new or reset account must change its password, and ADMIN or
  SECURITY_ENGINEER must enroll MFA, before any endpoint other than the setup flows responds.
- **TOTP replay protection.** The last accepted time-step is stored; a code is accepted once.
- **Admins never handle passwords.** New users are invited with a one-time link (72-hour expiry);
  the first admin comes from `make create-admin`, which prints a one-time password.
- **Browser session (frontend).** The access token is held in memory. Refresh is single-flight in
  a tab and serialized across tabs with the Web Locks API; without that, two tabs refreshing at
  once would present the same refresh token twice and trip reuse detection.

### Known limits (accepted for now)
- **One HS256 signing key, no `kid`.** Rotating it signs everyone out. Acceptable for a single
  service; asymmetric keys with rotation are a Phase 12 hardening candidate.
- **An MFA challenge token can be retried until it expires (5 minutes)**, so users can correct a
  typo. Guessing is bounded by the account lockout counter, which MFA failures share.
- **Lockout can be triggered by anyone who knows an email address** (a deliberate lockout is a
  nuisance attack). Mitigations arrive with the WAF rate-based rules (Phase 5) and per-IP limits
  (Phase 6).
