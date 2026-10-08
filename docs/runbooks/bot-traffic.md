# Runbook: Bot traffic and scanning

- **Severity guidance:** SEV3 by default (reconnaissance); SEV2 if scanning precedes injection or
  sign-in attacks from the same source, or a scanner found an exposed path.
- **Owner role:** ANALYST
- **Related threats / controls:** T-API-12, T-EDGE-01 · C-API-09, C-SO-02, C-SO-04
- **Last exercised:** 2026-10-07, attack simulator scenario "Bot and scanner activity"

## 1. Detection

| Signal | Where |
|---|---|
| SCAN-001: scanner user agents (sqlmap, nikto, nuclei and similar) | Threats page, *Category: Scanner* |
| RECON-001: requests for `.env`, `.git`, backups, admin consoles | Threats page, *Category: Reconnaissance* |
| **COR-006 Automated scanning**: 3+ scanner or recon events from one address in 10 minutes | Threats page (MEDIUM; no incident on its own) |
| Unknown-path requests | Dashboard → API traffic; API Security Center |

## 2. Triage (first 15 minutes)
1. Does the source do anything else? Threats → *Source IP*. Scanning followed by injection
   (COR-003) or sign-in failures (COR-001) means an attack is being prepared: follow those
   runbooks; their incidents gather the scanning events as evidence.
2. Did any recon request **succeed**? Probes under `/api/` should get 404 (and are counted as
   unknown paths). Outside `/api/`, the edge answers every path with the SPA's own `index.html`,
   so a 200 there is the app shell, not the file that was asked for. A response that really
   contains a sensitive file is SEV2: open an incident from the event.

## 3. Investigation
Check the probed paths against what the edge serves: nginx serves only the built SPA (its
`/assets/` return 404 for anything not built) and proxies `/api/`. The web image contains only the
build output, so there are no dotfiles, sources or backups to find.

## 4. Containment
Usually none: scanning is constant on the internet. AWS WAF Bot Control and IP reputation lists
(Phase 5) reduce it at the edge, changed through Terraform.

## 5. Remediation
If a path was exposed, remove it from the image or the nginx configuration and add a check for it
to `scripts/verify-hardening.sh`.

## 6. Validation
The path no longer returns the file; `make verify-hardening` passes with the new check.

## 7. Rollback
Not applicable unless a block was added; lift it through the same reviewed change.

## 8. Post-incident
Close any incident with *Resolved* or *False positive* (for example an authorised scan), with a
note naming who ran it.
