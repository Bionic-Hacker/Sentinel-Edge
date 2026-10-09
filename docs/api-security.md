# API security

What the API Security Center shows, where each figure comes from, and how the OWASP API Security
Top 10 (2023) is addressed. Everything here is **LOCAL**: no AWS resources are involved.

## The API Security Center

`/apis` in the app (ADMIN, SECURITY_ENGINEER, DEVELOPER), backed by the endpoints below. At
v0.7.0 the inventory lists **85 endpoints**: 23 from Phases 1 to 6, 22 for security operations
(Phase 7: security events, incidents, the dashboard overview, applications and the attack
simulator), 11 for vulnerability management (Phase 8: findings, risk acceptances, scans and
SBOMs), 23 for threat modeling and governance (Phase 10: the control catalogue, requirements,
threat models, the posture score, exceptions and change requests) and 6 for the AI security
engine (Phase 9: status, analyses and proposals; see [ai-security.md](ai-security.md)). Their roles
are in [authorization.md](authorization.md).

| Endpoint | Returns |
|---|---|
| `GET /api/v1/api-security/inventory` | Every endpoint with controls, 24-hour metrics and status |
| `GET /api/v1/api-security/owasp` | OWASP API Top 10 coverage with controls and test evidence |

For every endpoint (spec §14):

| Field | Source |
|---|---|
| Method, endpoint | The live route table |
| Authentication, authorization | The route's own guard dependencies (`public_endpoint`, `authenticated_setup`, `require_roles`), plus CSRF protection and any object-level rule |
| Risk rating | Policy registry: critical, high, medium or low inherent risk if the controls failed |
| Rate limit | Policy registry; enforced by the same entry ([ADR-0017](adr/0017-rate-limiting-and-client-ip.md)) |
| Request count, error rate | Hourly counters: requests, and (4xx + 5xx) / requests |
| Attack count | Security rejections: 401 + 403 + 429 responses. A signal, not a verdict. Classified attacks (injection, scanning, stuffing) are on the Threats page from HTTP analysis (Phase 7); WAF logs join them in Phase 5 |
| Last scan | The latest imported scan that included the authenticated ZAP API scan, which covers every endpoint in the OpenAPI document (Phase 8). Until one is imported, the note says to run `make dast` and `make scan-import` |
| Security status | `protected`; `elevated` when requests were throttled or there were 5+ forbidden responses in 24 hours; `review` when there were server errors |

The overview also counts **requests to unknown paths**, a sign of someone probing for
undocumented endpoints. Only the count is kept, never the path.

### Metrics privacy
Counters are stored per route template and hour. No IP addresses, user IDs, path parameters,
query strings or payloads are stored, so the table holds no personal data. Rows older than 30
days are pruned.

### Keeping the inventory honest
- A test fails if any route lacks a registry entry, or an entry outlives its route.
- A test compares the inventory's access description for every endpoint with the authorization
  matrix in `tests/security/test_authz_matrix.py`, which was written independently.
- A test fails if any test cited as OWASP evidence stops existing.

## OWASP API Security Top 10 (2023)

| Category | Status | How |
|---|---|---|
| API1 Broken Object Level Authorization | Mitigated | Service-layer ownership checks (users, applications, incidents); others' records return 404; denials audited; repeated denials detected (COR-004) |
| API2 Broken Authentication | Mitigated | Argon2id, MFA, short-lived tokens checked per request, refresh-token reuse detection, lockout, per-IP sign-in limits; stuffing detected (COR-001, COR-007) |
| API3 Broken Object Property Level Authorization | Mitigated | Response models allow-list fields; request models forbid unknown fields; route-table sweeps enforce both |
| API4 Unrestricted Resource Consumption | Partial | Token buckets per IP and account, page-size caps, 1 MB body limit, 15 s statement timeout. WAF rate rules in Phase 5 |
| API5 Broken Function Level Authorization | Mitigated | Roles declared on every route; sweep as every role |
| API6 Unrestricted Access to Sensitive Business Flows | Partial | Sign-in, MFA, recovery and invitations rate limited; no account enumeration. WAF Bot Control in Phase 5 |
| API7 Server Side Request Forgery | Not exposed | No endpoint fetches user URLs; outbound guard ready for Phase 9 |
| API8 Security Misconfiguration | Partial | Headers and CSP everywhere, Host allow-list, generic errors, docs off when deployed, hardened containers. Edge TLS in Phase 5 |
| API9 Improper Inventory Management | Mitigated | Inventory generated from the route table; registry must match; probes counted |
| API10 Unsafe Consumption of APIs | Not exposed | No third-party APIs consumed; Bedrock output contract in Phase 9 (ADR-0007) |

The live version, with cited tests, is in the app and at `/api/v1/api-security/owasp`.

## Attack detection on every request (Phase 7)
Every API request also passes through detect-only HTTP analysis: 17 rules for SQL injection,
XSS, path traversal, command injection, SSRF, scanners and reconnaissance, applied to the path,
query, headers and JSON body after double percent-decoding. Matches are recorded as security
events; nothing is blocked, because blocking belongs to the WAF at the edge
([ADR-0018](adr/0018-security-event-pipeline-and-incidents.md)). Snippets from sensitive fields
are stored as `[REDACTED]`, and incident free-text fields are excluded so that analysts can
write about an attack without triggering one.

## SSRF guard (OWASP API7)
`backend/app/security/egress.py` must approve any future outbound request. It requires HTTPS on
the default port with no credentials in the URL, prefers an explicit host allow-list, and refuses
a destination if **any** resolved address is not public. That covers loopback, RFC 1918,
link-local (including the metadata service at 169.254.169.254), carrier-grade NAT, multicast,
reserved and unique-local IPv6, and IPv4-mapped or 6to4 forms of all of them. Callers connect
to the approved addresses, not to a fresh DNS lookup, which defeats DNS rebinding.

## Operating it
- `make prune-rate-limits`: delete rate-limit buckets idle for over a day (also done
  automatically).
- A user locked out by a rate limit waits for `Retry-After`; there is no manual reset, by design.
- If the database is unreachable, the limiter fails closed: requests get `503` with
  `Retry-After: 5` until it returns.
- `ratelimit.exceeded` in the audit log marks the start of each throttled run, with policy, scope
  and endpoint.
