# Security headers

Applied by the API middleware (`backend/app/core/security_headers.py`) and the SPA edge
(`frontend/security-headers.conf` locally; CloudFront response-headers policy in Phase 5).
Tests assert the API headers on 200, 400, 404, 405, and 500 responses (ADR-0011).

| Header | API value | SPA value | Why |
|---|---|---|---|
| Content-Security-Policy | `default-src 'none'; frame-ancestors 'none'; base-uri 'none'` | `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'` | Primary XSS mitigation. The API returns JSON only, so nothing may load. The SPA allows only its own bundled scripts, styles, and fonts — no inline code, no `eval`, no third-party origins. Fonts are self-hosted so no external `font-src` is needed. |
| Strict-Transport-Security | `max-age=63072000; includeSubDomains` | same | Forces HTTPS for two years, preventing SSL stripping. Ignored by browsers over plain HTTP, so harmless locally. `preload` is deferred until the production domain is fixed, because preload is hard to undo. |
| X-Content-Type-Options | `nosniff` | same | Stops browsers from reinterpreting a response as a different (executable) type. |
| X-Frame-Options | `DENY` | same | Clickjacking defense for older browsers; `frame-ancestors 'none'` is the modern equivalent. |
| Referrer-Policy | `no-referrer` | same | Security UIs contain incident IDs and filters in URLs; never leak them to other sites. |
| Permissions-Policy | camera, microphone, geolocation, payment, USB, sensors disabled | same | Removes powerful browser features the platform never needs, limiting abuse after an XSS. |
| Cross-Origin-Opener-Policy | `same-origin` | same | Isolates the browsing context from cross-origin windows (tab-nabbing, XS-Leaks). |
| Cross-Origin-Resource-Policy | `same-origin` | same | Prevents other origins from embedding SentinelEdge responses. |
| Cache-Control | `no-store` | `no-cache` (HTML), `immutable` (hashed assets) | Security data must never sit in shared or browser caches. Hashed assets are safe to cache forever. |
| Server | removed | `server_tokens off` | Do not advertise implementation or version. |

Deliberately **not** set: `X-XSS-Protection` (deprecated; can introduce vulnerabilities in old
browsers) and `Expect-CT` (obsolete).
