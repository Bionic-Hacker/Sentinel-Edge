# Architecture Decision Records

All ADRs live in `docs/adr/`. Each records context, decision, security impact, alternatives considered and consequences. Implemented ADRs carry an *as implemented* addendum where reality refined the plan.

| ADR | Decision | Status | Phase |
|---|---|---|---|
| 0001 | Private origin: internal ALB behind CloudFront VPC origins | Accepted | 4–5 |
| 0002 | Single origin for SPA and API; no CORS | Accepted; local via nginx | 1, 5 |
| 0003 | Authentication: Argon2id, 15-min JWT in memory, rotating `__Host-` refresh cookie, TOTP MFA | Implemented | 2 |
| 0004 | Two-layer rate limiting: WAF at the edge, PostgreSQL token buckets in the app | App layer implemented | 5, 6 |
| 0005 | Tamper-evident audit log: hash chain, grants, triggers, Object Lock archive | Chain, grants, triggers implemented | 2, 4 |
| 0006 | Amazon Bedrock as AI provider, authenticated by IAM task role | Accepted | 9 |
| 0007 | AI output contract (schema-bound, evidence vs inference) and human approval | Accepted | 9 |
| 0008 | WAF changes only through Terraform; dashboard is read-only | Accepted; simulated WAF only in P7 | 5, 7, 10 |
| 0009 | Provenance classification (REAL_AWS, LOCAL, SIMULATED, DEMO) enforced by tests | Implemented | 1+ |
| 0010 | CI identity via GitHub OIDC; SHA-pinned actions; read-only token | Pinning implemented | 1, 11 |
| 0011 | Security headers at both the edge and the application | App + local edge implemented | 1, 5 |
| 0012 | Backend layering; explicit response models; `extra="forbid"` | Implemented | 1+ |
| 0013 | Security gates from Phase 1 (shift left) | Implemented | 1 |
| 0014 | Terraform state and per-environment isolation | Accepted | 3 |
| 0015 | Separate database roles for migrations and runtime | Implemented | 2, 4 |
| 0016 | Local-first phase order to defer AWS cost | Accepted (owner decision) | — |
| 0017 | Rate-limit implementation, endpoint policy registry, client-IP trust | Implemented | 6 |
| 0018 | Security event pipeline: detect-only HTTP analysis, synchronous correlation under the audit lock, incidents with write-once evidence and timeline digests in the audit chain | Implemented | 7 |
| 0019 | Attack simulator and simulated WAF: no network I/O, no target input, RFC 5737 addresses, AWS block/count semantics | Implemented | 7 |
