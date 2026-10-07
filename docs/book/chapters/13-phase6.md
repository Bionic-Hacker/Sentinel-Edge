# Phase 6 — API Security

<p class="lead">Phase 2 decided who may call each endpoint. Phase 6 adds how often, makes the whole API surface visible, and proves coverage of the OWASP API Security Top 10 with tests that can be run. Released as v0.3.0.</p>

## Milestones

| Milestone | Delivered |
|---|---|
| M0 | Housekeeping before API security work |
| M1 | PostgreSQL token-bucket rate limiting and trusted client IPs |
| M2 | API inventory, endpoint metrics and OWASP API Top 10 coverage |
| M3 | API Security Center page (`/apis`) |
| M4 | Documentation, smoke test (34 checks), v0.3.0 release notes |
| M5 | Reliable smoke burst, `503` when the limiter's database is down, settled test renders |

## One registry for every endpoint

`backend/app/core/api_policy.py` gives every route a **risk rating**, a **rate-limit policy**, its **OWASP API Top 10 exposure**, the **data it handles** and any **object-level rule**. The limiter and the inventory both read this registry, so what the inventory reports is what the code enforces. A test fails if the registry and the live route table differ in either direction (OWASP API9: improper inventory management). Authentication and authorization are *not* duplicated in the registry. They are read from each route's own guard dependencies, so they cannot disagree with them.

## Rate limiting (ADR-0017)

### The policies

| Policy | Limit | Keyed by | Endpoints |
|---|---|---|---|
| `ip_global` | 600 / min | IP | every API route, before authentication |
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

### An atomic token bucket in one SQL statement
Each bucket is one row per (policy, subject). A check is a single `INSERT … ON CONFLICT DO UPDATE` that refills the bucket for elapsed time, spends a token if one is available, and reports the outcome, all on **the database's clock**:

```sql
INSERT INTO sentinel.rate_limit_buckets AS b
    (bucket_key, tokens, updated_at, last_allowed, denied_since)
VALUES (:key, :capacity - 1, now(), true, NULL)
ON CONFLICT (bucket_key) DO UPDATE SET
    tokens = CASE
        WHEN LEAST(:capacity, b.tokens + EXTRACT(EPOCH FROM now() - b.updated_at) * :rate) >= 1
        THEN LEAST(:capacity, b.tokens + EXTRACT(EPOCH FROM now() - b.updated_at) * :rate) - 1
        ELSE LEAST(:capacity, b.tokens + EXTRACT(EPOCH FROM now() - b.updated_at) * :rate)
    END,
    last_allowed =
        LEAST(:capacity, b.tokens + EXTRACT(EPOCH FROM now() - b.updated_at) * :rate) >= 1,
    denied_since = CASE ... ELSE COALESCE(b.denied_since, now()) END,
    updated_at = now()
RETURNING tokens, last_allowed, (denied_since = updated_at) AS first_denial
```

Because the row lock taken by the upsert serializes concurrent checks, a bucket can never be overspent, whichever API instance handles the request. A 40-thread concurrency test proves it. The check runs on its own connection and commits immediately, so a request that later fails has still spent its token. Using the database clock means API instances with skewed clocks still agree.

:::why Why a token bucket, not a fixed window?
Fixed-window counters allow a double burst at window edges: a full window's worth just before the boundary, then another just after. A token bucket refills continuously, so the burst is bounded by the bucket's capacity at all times.
:::

### Two checkpoints
- **Per-IP, before authentication.** A router-level dependency on every API route applies the global ceiling plus the endpoint's own IP-keyed policy. A sign-in flood is rejected before any Argon2id hashing is spent on it.
- **Per-account, after authentication.** Applied right after the session is authenticated, so the limit follows the user across IP addresses.

### Responses and auditing
A denied request gets `429` with `Retry-After` and the standard error envelope. Allowed requests carry `RateLimit-Limit`, `RateLimit-Remaining` and `RateLimit-Reset`, following the IETF draft. Only the **first denial in a run** is audited (`ratelimit.exceeded`, with policy, scope and endpoint). Later denials are counted in metrics, so a flood cannot also flood the audit log (T-API-13).

### Guard rails
Rate limiting cannot be disabled in deployed environments; configuration validation refuses. Idle buckets are pruned after a day. If the limiter cannot reach its database it **fails closed**: the request is refused with `503` and `Retry-After: 5`, never allowed through unlimited.

## Trusting the right client IP

Every browser request reaches the API through a proxy (nginx locally; CloudFront and the ALB on AWS). Without proxy-header trust, every client appears to come from the proxy, so per-IP limits throttle everyone together and audit records name the proxy. Trusting `X-Forwarded-For` from anyone is worse: a client could choose its own address (T-ORG-02).

`ClientIpMiddleware` runs outermost and rewrites the ASGI client address once:

1. If the direct TCP peer is **not** inside `SENTINEL_TRUSTED_PROXY_CIDRS`, the header is ignored and the peer is the client.
2. Otherwise the header is walked **right to left**, skipping trusted proxies. The first untrusted address is the client.
3. A malformed hop stops the walk. Nothing to its left can be trusted.

Anything a client prepends to the header sits on the *left*, so it is never reached. Configuration rejects trust-all networks. Locally the edge Docker network is pinned to `172.30.86.0/24`, nginx overwrites the header with `$remote_addr`, and Uvicorn's own proxy handling is switched off, so there is exactly one decision point. Every consumer (rate limiting, audit, access logs) reads the same resolved address.

:::evidence Proven end to end
Twenty-two sign-in attempts were sent through nginx with a spoofed `X-Forwarded-For: 6.6.6.6`. The limiter returned 401s and then 429s with `Retry-After`. Exactly one `ratelimit.exceeded` audit record was written, naming the real client (172.30.86.1), not 6.6.6.6.
:::

## Route templates

FastAPI keeps included routers nested, so at request time the matched route knows only its router-relative path (`/{user_id}`), not the endpoint (`/api/v1/users/{user_id}`). At startup the app builds a map from each route object to its full template. The limiter, metrics and audit records all use it. This also fixed a Phase 2 defect: authorization-denial records had named router-relative paths and now record the full endpoint.

## Endpoint metrics

`ApiMetricsMiddleware` keeps hourly counters per route template in `api_endpoint_stats`: requests, client and server errors, 401s, 403s and 429s. Unmatched paths are counted together as "(unmatched)", a sign of someone probing for undocumented endpoints, and only the count is kept, never the path. **No IP addresses, user IDs, path parameters, query strings or payloads are stored**, so the table holds no personal data. Rows older than 30 days are pruned. Writes run in a worker thread, and a failure to write metrics never breaks a request.

## The API Security Center

The `/apis` page (ADMIN, SECURITY_ENGINEER and DEVELOPER) is backed by `GET /api/v1/api-security/inventory` and `GET /api/v1/api-security/owasp`. For every endpoint it shows the method and path, authentication, authorization (including CSRF and object rules), risk, rate limit, 24-hour requests, error rate, security rejections (401 + 403 + 429), last scan and a computed status:

- **protected** — controls in place, nothing notable;
- **elevated** — requests were throttled, or there were five or more forbidden responses in 24 hours;
- **review** — there were server errors.

The inventory's access description for every endpoint is cross-checked in a test against the independently written authorization matrix from Phase 2. Two separate sources must agree.

## OWASP API Security Top 10 (2023)

| Category | Status | How |
|---|---|---|
| API1 Broken Object Level Authorization | Mitigated | Service-layer ownership checks; others' records return 404; denials audited |
| API2 Broken Authentication | Mitigated | Argon2id, MFA, short-lived tokens checked per request, refresh reuse detection, lockout, per-IP sign-in limits |
| API3 Broken Object Property Level Authorization | Mitigated | Response models allow-list fields; request models forbid unknown fields; route-table sweeps enforce both |
| API4 Unrestricted Resource Consumption | Partial | Token buckets, page-size caps, 1 MB body limit, 15 s statement timeout. WAF rate rules in Phase 5 |
| API5 Broken Function Level Authorization | Mitigated | Roles declared on every route; sweep as every role |
| API6 Unrestricted Access to Sensitive Business Flows | Partial | Sign-in, MFA, recovery and invitations limited; no enumeration. WAF Bot Control in Phase 5 |
| API7 Server Side Request Forgery | Not exposed | No endpoint fetches user URLs; egress guard ready for Phase 9 |
| API8 Security Misconfiguration | Partial | Headers everywhere, Host allow-list, generic errors, docs off when deployed, hardened containers. Edge TLS in Phase 5 |
| API9 Improper Inventory Management | Mitigated | Inventory generated from the route table; registry must match; probes counted |
| API10 Unsafe Consumption of APIs | Not exposed | No third-party APIs consumed; Bedrock output contract in Phase 9 |

Each category in the live endpoint cites the specific tests that prove it, and a test fails if any cited test stops existing. "Partial" categories state what completes them. The claims cannot outrun the evidence.

## Route-table sweeps

Three tests walk the whole route table rather than sampling it:

- every request body model forbids unknown fields (mass assignment);
- every JSON route declares a response model (excessive data exposure);
- any response field whose name *looks* sensitive (hash, secret, token, password…) needs explicit, reasoned approval. Four were approved: `prev_hash`, `record_hash` and `head_hash` (audit verification needs them) and `must_change_password` (a boolean flag).

## SSRF guard

`app/security/egress.py` must approve any future outbound request. It requires HTTPS on the default port with no credentials in the URL, prefers an explicit host allow-list, and refuses a destination if **any** resolved address is not public. That covers loopback, RFC 1918, link-local (including the metadata service at 169.254.169.254), carrier-grade NAT, multicast, reserved and unique-local IPv6, and IPv4-mapped or 6to4 forms of all of them. Callers connect to the approved addresses rather than doing a fresh DNS lookup, which defeats DNS rebinding. Nothing calls out yet. The guard is ready, and tested, before the first integration needs it.

:::lesson Fixed during the phase
The smoke test's probe flood sent a fixed 125 requests, and on a slower machine the bucket refilled mid-burst and no 429 came back. It now sends until the first 429, which arrived after about 130 requests on the owner's machine. The limiter also originally answered a database outage with a generic 500. It now returns `503` with `Retry-After`, still refusing the request.
:::

:::evidence Verified in Phase 6
391 backend tests (99% coverage) and 45 frontend tests. `make smoke`: 34 checks, including a real rate-limit trip, an ignored spoofed `X-Forwarded-For`, and the inventory counting the throttled requests. `make verify-hardening`: 17 checks. Ruff, mypy (strict), Bandit, ESLint, TypeScript and the schema-drift check are clean. Verified in headless Chromium against a live API, PostgreSQL and nginx, with nothing in web storage.
:::
