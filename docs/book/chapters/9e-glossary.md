# Glossary and Edition History

## Glossary

| Term | Meaning |
|---|---|
| ADR | Architecture Decision Record: context, decision, security impact, alternatives, consequences |
| BOLA / BFLA | Broken Object / Function Level Authorization (OWASP API1 / API5) |
| CSP | Content Security Policy: browser-enforced allow-list of what a page may load or run |
| COEP / COOP | Cross-Origin Embedder / Opener Policy: headers that isolate a page from other origins |
| Control catalogue | Every control with its implementation and evidence, generated from `docs/security-controls.md` and loaded into the app |
| CSRF | Cross-Site Request Forgery |
| CycloneDX | An SBOM format: components, versions, package URLs and licences |
| DAST | Dynamic application security testing: attacking the running application |
| Exception (EXC-n) | A time-limited, approved decision to live with a risk, with its compensating control |
| Fail closed | On error, refuse the action rather than allow it |
| Fingerprint | A finding's stable identity across scans, used to de-duplicate it |
| Hash chain | Records each include the hash of the previous one, so any change breaks every later hash |
| `__Host-` cookie | Cookie prefix the browser accepts only with `Secure`, `Path=/` and no `Domain` |
| OAC | Origin Access Control: CloudFront's signed access to a private S3 bucket |
| OIDC | OpenID Connect: lets CI assume a cloud role without stored keys |
| Posture score | Per category: control coverage minus named live signals; `built_scope` averages only the measured categories |
| Provenance | Whether a capability or record is REAL_AWS, LOCAL, SIMULATED or DEMO |
| Route template | An endpoint's full path pattern, such as `/api/v1/users/{user_id}` |
| SAST / SCA | Static analysis of source code / analysis of third-party dependencies |
| SBOM | Software Bill of Materials |
| Separation of duties | Whoever requests an exception or change cannot approve it |
| Scan gate | The step that decides from all scan reports whether a build may proceed |
| SLA | Here, the remediation deadline a finding's severity sets |
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
| 2 | October 7, 2026 | v0.4.0 | Phase 7 (security operations) rewritten as built, with the detection pipeline and incident workflow figures; request pipeline updated for HTTP analysis; ADR-0018 and ADR-0019; nine new threats and controls; 45-endpoint inventory; Phase 7 reproduction steps; new lessons. |
| 3 | October 8, 2026 | v0.5.0 | Phase 8 (application security scanning) rewritten as built, with the scan pipeline and finding lifecycle figures; ADR-0020 and ADR-0021; eight new threats and fourteen new controls; 56-endpoint inventory; scanning and vulnerability management reproduction steps; new lessons. Phase 10 marked next. |
| 4 | October 8, 2026 | v0.6.0 | Phase 10 (threat modeling and governance) moved to Part II and rewritten as built, with the catalogue and exception lifecycle figures; ADR-0022 and ADR-0023; nine new threats, six new controls and a governance layer; 79-endpoint inventory; governance reproduction steps; new lessons. Phase 9 marked next. |

Each new phase release produces a new edition. The completed phase's chapter moves from Part III to Part II and is rewritten as built, and the status tables, figures, appendices and lessons are updated.
