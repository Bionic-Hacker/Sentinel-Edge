# ADR-0002: Single origin for SPA and API

- **Status:** Accepted
- **Date:** 2026-10-06
- **Phase:** 1 (local, via nginx), 5 (CloudFront)

## Context
Serving the SPA and API from different origins requires CORS, which is a frequent source of
misconfiguration (reflected origins, credentialed wildcards) and complicates cookie security.

## Decision
One hostname. CloudFront routes `/api/*` to the internal ALB (no caching, all methods) and
everything else to a private S3 bucket through Origin Access Control. Locally, the `web`
container (nginx) plays the same role. The SPA calls only relative `/api/v1/...` paths; the
API client rejects absolute and protocol-relative URLs.

## Security impact
- No CORS policy to get wrong; the API sends no `Access-Control-Allow-*` headers at all.
- Refresh-token cookies (Phase 2) can be `SameSite=Strict` and host-only.
- One WAF web ACL and one response-headers policy cover all traffic.
- Controls C-API-05, C-WEB-02.

## Alternatives considered
Separate `app.` and `api.` hostnames with CORS — rejected for the reasons above.

## Consequences
CloudFront cache behaviours must be precise: `/api/*` uses `CachingDisabled` and forwards
`Authorization` and cookies; the SPA behaviour forwards neither.
