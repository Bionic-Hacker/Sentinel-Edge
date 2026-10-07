# ADR-0017: Rate-limit implementation, endpoint policy registry, and client IP trust

- **Status:** Accepted
- **Date:** 2026-10-07
- **Phase:** 6
- **Builds on:** ADR-0004 (two-layer rate limiting), ADR-0001 (private origin), ADR-0012 (layering)

## Context
ADR-0004 chose an application-layer token-bucket limiter in PostgreSQL to complement AWS WAF
rate-based rules. Phase 6 implements it and must decide where policies live, how limits are
keyed, what the limiter trusts as the client address, and how the API Security Center reports
all of it without drifting from what the code enforces.

Three facts shaped the design:

1. Every browser request reaches the API through a reverse proxy (nginx locally, ALB and
   CloudFront in AWS). Without proxy-header trust, every client shares the proxy's address, so
   per-IP limits throttle everyone together and audit records name the proxy, not the client.
2. Trusting `X-Forwarded-For` from anyone lets a client choose its own IP (threat T-ORG-02).
3. FastAPI keeps included routers nested: at request time the matched route knows only its
   router-relative path (`/{user_id}`), not the endpoint (`/api/v1/users/{user_id}`).

## Decision

**One endpoint policy registry** (`backend/app/core/api_policy.py`) gives every route a risk
rating, a rate-limit policy, its OWASP API Top 10 exposure and the data it handles. A test
fails if the registry and the live route table differ in either direction (OWASP API9). The
limiter and the inventory both read the registry, so the inventory reports what is enforced.
Authentication and authorization are not duplicated there: they are read from each route's own
guard dependencies.

**Token buckets in PostgreSQL**, one row per (policy, subject). Each check is a single atomic
`INSERT … ON CONFLICT DO UPDATE` that refills the bucket for elapsed time, spends a token if
available, and reports the result, using the database clock. It runs on its own connection and
commits immediately, so a request that later fails has still spent its token. A 40-thread
concurrency test proves a bucket is never overspent.

**Two checkpoints.** Per-IP limits run as a router-level dependency on every API route, before
authentication: a global ceiling (600/min) plus the endpoint's own policy when that policy is
keyed by IP (sign-in, MFA, refresh, recovery, probes). Floods are rejected before any password
hashing. Per-account limits run immediately after the session is authenticated, so they follow
the user across IP addresses.

**Responses.** A denied request gets `429` with `Retry-After` and the standard error envelope;
allowed requests carry `RateLimit-Limit`, `RateLimit-Remaining` and `RateLimit-Reset`. The first
denial in a run is audited (`ratelimit.exceeded`); later denials are counted in API metrics
only, so a flood cannot also flood the audit log.

**Client IP.** `ClientIpMiddleware` runs outermost and rewrites the ASGI client address once.
It honours `X-Forwarded-For` only when the direct peer is inside `SENTINEL_TRUSTED_PROXY_CIDRS`,
walking the header right to left and skipping trusted hops, so entries a client prepends are
ignored. Configuration rejects trust-all networks. Locally the edge Docker network is pinned to
`172.30.86.0/24` and nginx overwrites the header with the real peer. Uvicorn's own proxy
handling is switched off so there is exactly one decision point.

**Route templates.** At start-up the app maps each route object to its full template; the
limiter, metrics and audit records use that map.

**Guard rails.** Rate limiting cannot be disabled in deployed environments (config validation).
Idle buckets are pruned after a day.

## Policies

| Policy | Limit | Keyed by | Endpoints |
|---|---|---|---|
| `ip_global` | 600 / min | IP | every API route (before authentication) |
| `probe` | 120 / min | IP | `/health`, `/ready` |
| `login` | 20 / 2 min | IP | `POST /auth/login` |
| `mfa_verify` | 20 / 2 min | IP | `POST /auth/mfa/verify` |
| `token_refresh` | 30 / min | IP | `POST /auth/refresh` |
| `account_recovery` | 5 / 15 min | IP | password forgot and reset |
| `session` | 60 / min | user | `/auth/me`, `/auth/logout` |
| `credential_change` | 10 / 5 min | user | password change, MFA enrollment |
| `read` | 120 / min | user | list and read endpoints |
| `admin_write` | 30 / min | user | user administration |
| `expensive` | 6 / min | user | audit chain verification |

Account lockout (5 failures) still applies per account; WAF rate-based rules add a volume limit
at the edge in Phase 5.

## Security impact
Mitigates T-ID-01 (credential stuffing), T-API-04 (resource consumption), T-ID-10 (deliberate
lockout, now bounded per IP) and T-ORG-02 (spoofed client IP). Implements C-API-03, C-API-09 and
C-NET-03. Audit source IPs become the real client.

## Alternatives considered
- **Fixed-window counters:** simpler, but allow double bursts at window edges.
- **In-memory limiter:** inconsistent across API tasks and lost on restart.
- **Redis/ElastiCache:** correct and fast, but adds cost the project defers (ADR-0004, ADR-0016).
- **Uvicorn `--proxy-headers`:** trusts a list of addresses but cannot express CIDR ranges per
  environment or skip chained proxies, and would be a second, separate decision point.

## Consequences
One database write per limited request, plus one metrics write per API request: acceptable at
portfolio scale, revisited in Phase 12. Changing the local edge subnet requires
`docker compose down` once, because Docker networks cannot be re-addressed in place.
