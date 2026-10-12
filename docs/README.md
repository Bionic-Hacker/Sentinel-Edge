# Documentation index

Documents are written in the phase that builds what they describe, so nothing here describes a
system that doesn't exist yet as if it did.

| Document | Covers | Status |
|---|---|---|
| [book/](book/) | **The engineering book (PDF):** build plan, blueprint, phases as built, reproduction guide | Rebuilt every release |
| [architecture.md](architecture.md) | Target and local architecture, components, data model, roles | Phase 1 |
| [threat-model.md](threat-model.md) | STRIDE per trust boundary, attack paths, residual risk; loaded into the app as SentinelEdge's own model | v0.8 (Phase 3) |
| [security-controls.md](security-controls.md) | Defense-in-depth layers, control catalogue, control matrix | Phase 1; updated every phase |
| [feature-classification.md](feature-classification.md) | REAL_AWS / LOCAL / SIMULATED / DEMO rules and register | Phase 1 |
| [security-headers.md](security-headers.md) | Every header and why it is set | Phase 1 |
| [secure-sdlc.md](secure-sdlc.md) | Security definition of done for each phase | Phase 1 |
| [local-development.md](local-development.md) | Running and testing locally | Phase 1 |
| [authorization.md](authorization.md) | Roles and the endpoint permission matrix | Phase 2 |
| [governance/exceptions.md](governance/exceptions.md) | Where security exceptions live now (the application) and the rules they follow | Phase 2; moved to the app in Phase 10 |
| [api-security.md](api-security.md) | API Security Center, metrics, OWASP API Top 10 coverage, SSRF guard | Phase 6 |
| [bedrock-setup.md](bedrock-setup.md) | Using Amazon Bedrock for the AI engine: a one-model role, short-lived credentials, cost bounds | Phase 9; Phase 3 (this account) |
| [aws-setup.md](aws-setup.md) | The AWS account and its constraints, signing in, the Terraform stacks, the domain, standing costs, teardown | Phase 3 |
| [../terraform/README.md](../terraform/README.md) | Terraform stacks, state, guards, layout, how it is tested and scanned | Phase 3 |
| [adr/](adr/) | Architecture decision records 0001–0025 | Phase 1–10, 3 |
| [runbooks/](runbooks/) | Operational runbooks: compromised credential (Phase 2); credential stuffing, SQL injection, API abuse, bot traffic (Phase 7); vulnerability remediation (Phase 8); AI prompt injection (Phase 9); governance (Phase 10); AWS cost runaway (Phase 3) | Phase 2, 3, 7–10 |
| aws-security.md | The deployed workload's IAM roles, KMS, secrets and logging (the foundation's are in aws-setup.md and the controls catalogue) | Phase 4 |
| cost.md | The deploy window's resource inventory, estimates and destroy checklist (standing costs: aws-setup.md) | Phase 4 |
| waf.md | Rule groups, rate rules, exceptions, change workflow | Phase 5 |
| cdn-security.md | CloudFront, origin protection, cache behaviours | Phase 5 |
| certificate-management.md | ACM lifecycle, DNS validation, trust chains, renewal, revocation | Phase 5 |
| [incident-response.md](incident-response.md) | Detection to incident, lifecycle, roles, evidence handling | Phase 7 |
| vulnerability-management.md | Sources, severity, SLAs, statuses | Phase 8 |
| sbom.md | Generation, storage, use | Phase 8 |
| devsecops.md | Pipeline stages and gates | Phase 8, 11 |
| [ai-security.md](ai-security.md) | The AI engine: what it sends, providers, limits, roles, safeguards, endpoints | Phase 9 |
| disaster-recovery.md | Backups, restore, RTO/RPO | Phase 12 |
