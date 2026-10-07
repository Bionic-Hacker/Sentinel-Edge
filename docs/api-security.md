# API security

What the API Security Center shows, where each figure comes from, and how the OWASP API Security
Top 10 (2023) is addressed. Everything here is **LOCAL**: no AWS resources are involved.

## The API Security Center

`/apis` in the app (ADMIN, SECURITY_ENGINEER, DEVELOPER), backed by:

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
| Attack count | Security rejections: 401 + 403 + 429 responses. A signal, not a verdict; attack classification arrives with WAF logs (Phase 5–7) |
| Last scan | Not scanned yet: authenticated DAST runs arrive in Phase 8 |
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
| API1 Broken Object Level Authorization | Mitigated | Service-layer ownership checks; others' records return 404; denials audited |
| API2 Broken Authentication | Mitigated | Argon2id, MFA, short-lived tokens checked per request, refresh-token reuse detection, lockout, per-IP sign-in limits |
| API3 Broken Object Property Level Authorization | Mitigated | Response models allow-list fields; request models forbid unknown fields; route-table sweeps enforce both |
| API4 Unrestricted Resource Consumption | Partial | Token buckets per IP and account, page-size caps, 1 MB body limit, 15 s statement timeout. WAF rate rules in Phase 5 |
| API5 Broken Function Level Authorization | Mitigated | Roles declared on every route; sweep as every role |
| API6 Unrestricted Access to Sensitive Business Flows | Partial | Sign-in, MFA, recovery and invitations rate limited; no account enumeration. WAF Bot Control in Phase 5 |
| API7 Server Side Request Forgery | Not exposed | No endpoint fetches user URLs; outbound guard ready for Phase 9 |
| API8 Security Misconfiguration | Partial | Headers and CSP everywhere, Host allow-list, generic errors, docs off when deployed, hardened containers. Edge TLS in Phase 5 |
| API9 Improper Inventory Management | Mitigated | Inventory generated from the route table; registry must match; probes counted |
| API10 Unsafe Consumption of APIs | Not exposed | No third-party APIs consumed; Bedrock output contract in Phase 9 (ADR-0007) |

The live version, with cited tests, is in the app and at `/api/v1/api-security/owasp`.

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
- `ratelimit.exceeded` in the audit log marks the start of each throttled run, with policy, scope
  and endpoint.
