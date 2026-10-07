# ADR-0011: Security headers at both the edge and the application

- **Status:** Accepted — application and local edge in Phase 1; CloudFront in Phase 5
- **Date:** 2026-10-06

## Decision
Set security headers in three places with intentionally different policies:
1. **API middleware** — strictest CSP (`default-src 'none'`), `no-store` caching.
2. **Local nginx** (`frontend/security-headers.conf`) — SPA CSP with no `unsafe-inline` or
   `unsafe-eval`.
3. **CloudFront response-headers policy** (Phase 5) — the SPA policy at the edge.

Header rationale is in `docs/security-headers.md`.

## Security impact
If the edge is misconfigured or bypassed, the application still protects itself; if the app
regresses, the edge still applies headers. Tests assert headers on 200, 404, 400, and 500
responses.

## Consequences
Policies must be kept consistent; Phase 5 adds a test comparing the CloudFront policy with
`security-headers.conf`.
