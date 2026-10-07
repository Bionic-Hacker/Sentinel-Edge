# ADR-0003: Authentication and session architecture

- **Status:** Accepted (implementation in Phase 2)
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
