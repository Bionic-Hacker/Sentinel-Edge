# Phase 1 — Architecture and Secure Foundation

<p class="lead">Phase 1 produced no user-facing features. It produced the decisions, the threat model, the repository and a local environment where every later phase inherits enforcement rather than retrofitting it. Release v0.1.0.</p>

## Goals

- Record the target architecture, the threat model and the control matrix before writing features.
- Write the first fourteen ADRs, covering every decision with security trade-offs that later phases depend on.
- Build a local environment whose trust boundaries mirror the AWS design.
- Put cross-cutting security mechanisms (headers, errors, logging, configuration) in place once, for every endpoint that follows.
- Ship real security gates from day one, rather than waiting for the scanning phase.

## Repository layout

```
Sentinel-Edge/
  backend/            FastAPI application, Alembic migrations, tests
  frontend/           React SPA, nginx config and security headers
  db/                 bootstrap-roles.sh (used locally, in CI and on RDS)
  docs/               architecture, threat model, controls, ADRs, runbooks, releases
  scripts/            smoke test, hardening verification, startup diagnosis
  terraform/          AWS modules (Phase 3 onward)
  scenarios/, tools/  attack scenarios (Phase 7), security CLI tools (Phase 11)
  .github/            CI workflow, Dependabot, CODEOWNERS, PR template
  docker-compose.yml  local topology    Makefile  single entry point
```

## Decisions recorded up front

Phase 1 wrote ADR-0001 to ADR-0014 before any feature code. These include the private origin, single-origin routing, the authentication architecture, two-layer rate limiting, the tamper-evident audit log, Bedrock as the AI provider, the AI output contract, WAF changes through Terraform, provenance classification, CI identity through OIDC, headers at two layers, backend layering, shift-left gates, and Terraform state isolation. Writing them first meant Phases 2 and 6 implemented decisions instead of inventing them under pressure. Each later ADR carries an *as implemented* addendum where reality refined the plan.

## Cross-cutting mechanisms

### Security middleware
A pure-ASGI middleware runs on every response, *including* 400, 404, 405 and 500 errors and rejected hosts. It sets the security headers, assigns a correlation ID, removes the server banner, and writes a structured access log containing the path only, never query strings, since those can carry tokens.

| Header | API value | Purpose |
|---|---|---|
| Content-Security-Policy | `default-src 'none'; frame-ancestors 'none'; base-uri 'none'` | The API returns JSON only, so nothing may load |
| Strict-Transport-Security | `max-age=63072000; includeSubDomains` | Forces HTTPS for two years; `preload` deferred until the domain is fixed |
| X-Content-Type-Options | `nosniff` | No MIME reinterpretation |
| X-Frame-Options / frame-ancestors | `DENY` / `'none'` | Clickjacking |
| Referrer-Policy | `no-referrer` | Security UIs put incident IDs in URLs |
| Permissions-Policy | camera, microphone, geolocation, payment, USB, sensors off | Limits post-XSS abuse |
| COOP / CORP | `same-origin` | Cross-origin isolation |
| Cache-Control | `no-store` | Security data never cached |

The SPA's nginx applies a strict policy with no `unsafe-inline` and no `unsafe-eval`. Fonts are self-hosted, so no third-party origin appears anywhere in the CSP. `X-XSS-Protection` and `Expect-CT` are deliberately not set: one is deprecated and harmful in old browsers, the other obsolete.

### Correlation IDs
An upstream `X-Request-ID` is accepted only if it matches `^[A-Za-z0-9-_.]{8,64}$`. Otherwise a new one is generated. A hostile value therefore cannot be used for log injection or header splitting.

### Error envelope
Every error has one shape: `{"error": {"code", "message", "correlation_id", "details?"}}`. Validation errors report the field location and error type, never the submitted value, so input is not reflected. Unhandled exceptions return a generic 500 with a correlation ID. Stack traces, SQL and internal paths go to the log, never to the client.

### Structured logging
Logs are JSON to stdout. Keys matching password, secret, token, authorization, cookie, API key, session or private key are replaced with `[REDACTED]`, recursively. Control characters are neutralized to prevent log forging.

### Secure-by-default configuration
Settings are validated at startup by Pydantic. Unknown environments are rejected, wildcard Host allow-lists are rejected, DEBUG is refused in deployed environments, and interactive API docs are forced off when deployed. A Host allow-list (`TrustedHostMiddleware`) returns 400 for unexpected Host headers.

### Capability register
The provenance enum and capability register (ADR-0009) were built in Phase 1, so every later feature is born with a label.

## Hardened containers

The backend image is a multi-stage build. The builder installs **hash-pinned** dependencies (`pip install --require-hashes --no-deps`) into a virtual environment. The runtime stage copies only that environment and the application, owned by root but run as UID 10001 with no shell. Compose adds a read-only root filesystem, `cap_drop: [ALL]`, `no-new-privileges` and `tmpfs` for `/tmp`. Uvicorn runs with `--no-server-header`, `--no-access-log` (the middleware logs instead) and `--no-proxy-headers`.

`make verify-hardening` proves these properties against the running stack. It checks that every service runs non-root with a read-only root filesystem, no effective capabilities and no-new-privileges; that the database port is not published and its network is internal; that the API and web are bound to localhost; that a forged Host header gets 400; that the API's CSP is deny-all and the SPA's CSP has no `unsafe-inline`; and that no Server header is disclosed.

## Shift-left gates (ADR-0013)

The specification places full scanning in Phase 8. A security project that ran without secret scanning or SAST for seven phases would contradict its own story, so Phase 1 shipped a minimal but real gate set in **pre-commit** and **CI**:

| Gate | Tool | Where |
|---|---|---|
| Secret scanning (full history) | Gitleaks, detect-private-key | pre-commit, CI |
| Python lint + security rules | Ruff (including the `S` bandit family) | pre-commit, CI |
| SAST | Bandit | pre-commit, CI |
| Type safety | mypy strict | CI |
| SCA | pip-audit (hash-pinned), npm audit (`--audit-level=high`) | CI |
| Frontend security lint | ESLint bans `dangerouslySetInnerHTML`, `innerHTML`, `eval`, web storage | pre-commit, CI |
| Coverage floor | pytest `--cov-fail-under=90` | CI |
| Branch safety | `no-commit-to-branch` (no direct commits to main) | pre-commit |

The CI workflow runs with `permissions: contents: read`, pins every third-party action to a full commit SHA, and checks out with `persist-credentials: false`. Dependabot proposes updates. CODEOWNERS requires owner review on security-sensitive paths. npm installs use `npm ci --ignore-scripts`, so a dependency cannot run code at install time.

:::evidence Verified in Phase 1
`make check` passes every gate locally. The API runs as a non-zero UID. Writing to the root filesystem fails with "Read-only file system". Port 5432 refuses connections from the host. A forged Host header returns 400. CI is green on the first push.
:::

## Talking points

- "Security gates existed from the first commit. Phase 8 adds scanners, it doesn't introduce scanning."
- "Every error, including 404s and 500s, carries the security headers, and there's a test for each status code."
- "The capability register means the platform can't claim a control it doesn't have, and that's enforced by tests, not by a style guide."
