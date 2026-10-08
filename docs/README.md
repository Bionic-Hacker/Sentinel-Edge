# Documentation index

Documents are written in the phase that builds what they describe, so nothing here describes a
system that doesn't exist yet as if it did.

| Document | Covers | Status |
|---|---|---|
| [book/](book/) | **The engineering book (PDF):** build plan, blueprint, phases as built, reproduction guide | Rebuilt every release |
| [architecture.md](architecture.md) | Target and local architecture, components, data model, roles | Phase 1 |
| [threat-model.md](threat-model.md) | STRIDE per trust boundary, attack paths, residual risk | v0.4 (Phase 7); full in Phase 10 |
| [security-controls.md](security-controls.md) | Defense-in-depth layers, control catalogue, control matrix | Phase 1; updated every phase |
| [feature-classification.md](feature-classification.md) | REAL_AWS / LOCAL / SIMULATED / DEMO rules and register | Phase 1 |
| [security-headers.md](security-headers.md) | Every header and why it is set | Phase 1 |
| [secure-sdlc.md](secure-sdlc.md) | Security definition of done for each phase | Phase 1 |
| [local-development.md](local-development.md) | Running and testing locally | Phase 1 |
| [authorization.md](authorization.md) | Roles and the endpoint permission matrix | Phase 2 |
| [governance/exceptions.md](governance/exceptions.md) | Security exceptions register (requester, justification, compensating control, expiry) | Phase 2 |
| [api-security.md](api-security.md) | API Security Center, metrics, OWASP API Top 10 coverage, SSRF guard | Phase 6 |
| [adr/](adr/) | Architecture decision records 0001–0021 | Phase 1–8 |
| [runbooks/](runbooks/) | Operational runbooks: compromised credential (Phase 2); credential stuffing, SQL injection, API abuse, bot traffic (Phase 7); 12 by Phase 12 | Phase 2, 7 |
| aws-security.md | IAM roles, network, KMS, CloudTrail | Phase 3–4 |
| terraform-security.md | Module design, state, Checkov policy | Phase 3 |
| cost.md | Resource inventory, estimates, destroy procedure | Phase 3–4 |
| waf.md | Rule groups, rate rules, exceptions, change workflow | Phase 5 |
| cdn-security.md | CloudFront, origin protection, cache behaviours | Phase 5 |
| certificate-management.md | ACM lifecycle, DNS validation, trust chains, renewal, revocation | Phase 5 |
| [incident-response.md](incident-response.md) | Detection to incident, lifecycle, roles, evidence handling | Phase 7 |
| vulnerability-management.md | Sources, severity, SLAs, statuses | Phase 8 |
| sbom.md | Generation, storage, use | Phase 8 |
| devsecops.md | Pipeline stages and gates | Phase 8, 11 |
| ai-security.md | Bedrock integration, guardrails, approval | Phase 9 |
| disaster-recovery.md | Backups, restore, RTO/RPO | Phase 12 |
