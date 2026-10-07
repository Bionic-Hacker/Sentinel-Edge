# Glossary and Edition History

## Glossary

| Term | Meaning |
|---|---|
| ADR | Architecture Decision Record: context, decision, security impact, alternatives, consequences |
| BOLA / BFLA | Broken Object / Function Level Authorization (OWASP API1 / API5) |
| CSP | Content Security Policy: browser-enforced allow-list of what a page may load or run |
| CSRF | Cross-Site Request Forgery |
| Fail closed | On error, refuse the action rather than allow it |
| Hash chain | Records each include the hash of the previous one, so any change breaks every later hash |
| `__Host-` cookie | Cookie prefix the browser accepts only with `Secure`, `Path=/` and no `Domain` |
| OAC | Origin Access Control: CloudFront's signed access to a private S3 bucket |
| OIDC | OpenID Connect: lets CI assume a cloud role without stored keys |
| Provenance | Whether a capability or record is REAL_AWS, LOCAL, SIMULATED or DEMO |
| Route template | An endpoint's full path pattern, such as `/api/v1/users/{user_id}` |
| SBOM | Software Bill of Materials |
| SSRF | Server-Side Request Forgery |
| STRIDE / PASTA | Threat-modeling methods: threat categories per element / risk-centric process |
| Token bucket | Rate-limiting algorithm: tokens refill continuously, each request spends one |
| TOTP | Time-based one-time password (authenticator apps) |
| VPC origin | CloudFront feature to reach a private, internal load balancer directly |
| WAF | Web Application Firewall |

## Edition history

| Edition | Date | Release | Changes |
|---|---|---|---|
| 1 | October 7, 2026 | v0.3.0 | First edition. Phases 1, 2 and 6 as built; remaining phases as designed; reproduction guide. |

Each new phase release produces a new edition. The completed phase's chapter moves from Part III to Part II and is rewritten as built, and the status tables, figures, appendices and lessons are updated.
