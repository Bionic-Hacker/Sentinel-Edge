# ADR-0004: Two-layer rate limiting

- **Status:** Accepted
- **Date:** 2026-10-06
- **Phase:** 5 (WAF), 2 and 6 (application)

## Context
Credential stuffing and API abuse need limits that hold across many ECS tasks. ElastiCache would
provide a shared counter store but adds roughly $12+/month to a cost-constrained project.

## Decision
- **Edge layer (REAL_AWS):** AWS WAF rate-based rules, scoped per path (`/api/v1/auth/*` tight,
  `/api/*` general) and keyed by IP (later also by forwarded header where appropriate).
- **Application layer (LOCAL):** a token-bucket limiter backed by PostgreSQL for identity-aware
  limits WAF cannot express (per account, per API key, per role), plus account lockout.

## Security impact
Defense in depth for T-ID-01 and T-API-04: WAF absorbs volume cheaply at the edge; the app
enforces per-identity limits that survive IP rotation. Controls C-WAF-03, C-API-03.

## Alternatives considered
In-memory per-task limiter (inconsistent across tasks); ElastiCache Redis (cost).

## Consequences
Database writes on auth paths; acceptable at portfolio scale and revisited in Phase 12.

## Addendum (Phase 6, 2026-10-07)
Implemented as decided. Details (policy registry, atomic bucket statement, per-IP and
per-account checkpoints, audit-once behaviour, trusted client IPs) are in
[ADR-0017](0017-rate-limiting-and-client-ip.md). Per-API-key limits wait until API keys exist.
