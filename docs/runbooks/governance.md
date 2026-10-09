# Runbook: Governance (exceptions, changes, threat model review)

- **Severity guidance:** SEV2: a critical or high exception expired while its issue is still
  present, a change that weakened a control failed validation, or a decision was made outside
  the workflow. SEV3: an exception within 14 days of expiry, a request waiting more than seven
  days, or a posture category that dropped since the last snapshot.
- **Owner role:** SECURITY_ENGINEER (decisions, reviews); ADMIN (second lead); DEVELOPER
  (requests and models for their own applications)
- **Related threats / controls:** T-GOV-01..09, T-VM-02, T-WAF-01; C-GOV-01..10, C-API-01;
  ADR-0022, ADR-0023
- **Last exercised:** 2026-10-08, `make smoke`: an exception refused for self-approval, then
  withdrawn with a reason; a change request refused for self-approval, then cancelled. EXC-0001
  and EXC-0002 migrated from the Markdown register.

## 1. Detection
- **Compliance > Posture:** each category lists the deductions behind its score. The governance
  category shows approved high or critical exceptions in force and requests waiting more than
  seven days. The trend shows daily snapshots.
- **Compliance > Exceptions:** status and days left for each exception. An exception past its date
  appears as *Expired* (the sweep runs on every read).
- **Compliance > Changes:** requests by status. Look for *Implemented* with no validation, or
  *Rolled back*.
- **Audit log:** `exception.*`, `change_request.*`, `threat_model.*` and
  `governance.catalogue_synced` actions. A developer reaching for another application's record
  appears as `authz.denied` (reason `not_owner`).
- **CI:** `test_the_shipped_catalogue_is_exactly_what_the_documents_produce` fails when a
  document changed without `make governance-catalogue`.

## 2. Triage (first 15 minutes)
1. **Exception about to expire or expired:** is the issue still present? For a scan finding, check
   the finding on the Vulnerabilities page. If it has been fixed, close the exception early with the
   fix reference. If it has not, it needs either a fix or a new exception (renewal is a new request
   with a new review, never an edit).
2. **Change failed validation:** roll it back now (step 7). The change is incomplete until it is
   validated.
3. **A decision that skipped the workflow** (for example a WAF rule mode changed with no change
   request, or a gate exception added to the file by hand): treat as SEV2 and open an incident.
   The audit log shows who did what.
4. **Catalogue drift in CI:** not an incident. Regenerate and commit (step 5).

## 3. Investigation
- **History:** each exception and change request shows its timeline, read from the
  hash-chained audit log. `make verify-audit` confirms the chain is intact.
- **Scope of an exception:** its application, scope, linked controls and, for a scan finding, the
  rule and component that `accepted-findings.toml` lists.
- **What a model says:** open the threat model from Threat Modeling. Each threat links to its
  controls. Compliance > Controls shows which threats each control mitigates and the evidence
  that proves it.
- **Who may act:** the API returns `permissions` and `available_moves` per record. When a button
  is missing, a role rule or separation of duties is the cause, not a bug. The page shows why.

## 4. Containment
- **Expired critical or high exception with the issue still present:** reduce exposure first
  (disable the feature, restrict the endpoint). Any WAF change goes through a change request
  (simulated WAF here; Terraform in Phase 5, ADR-0008). Then request a new exception with that
  compensating control and the shortest workable expiry.
- **A change that weakened a control:** roll back (step 7).
- **Unauthorised decision:** deactivate the account responsible or change its role (Users page;
  either ends its sessions at once), then
  follow the [compromised credential](compromised-credential.md) runbook.

## 5. Remediation
| Situation | Action |
|---|---|
| Scan-finding exception decided | `make accepted-risks` (stack running), review the diff, commit `scanning/accepted-findings.toml` |
| Threat model or controls document edited | `make governance-catalogue`, commit `backend/app/governance/catalogue.json` with the documents |
| New threat for SentinelEdge | Add it to `docs/threat-model.md` with control IDs; the app shows it after the next deploy |
| New threat for another application | A lead adds it to that application's model in Threat Modeling |
| Application model no longer needed | Archive it (kept, hidden); only a lead deletes permanently, and the audit log keeps a summary |
| Change approved | Implement it with a reference (pull request or ticket), then validate with the evidence |

## 6. Validation
1. **Exception:** its status is *Approved* with an expiry inside the limit, or *Closed* with the fix.
   For a scan finding, `make scan` passes or blocks as the register now says.
2. **Change:** a lead moves it to *Validated* with the result of the validation plan. A
   `waf_rule` change shows the new rule mode in the WAF simulator.
3. **Catalogue:** `make check` passes, and the Compliance page shows the new controls and
   threats.
4. **Posture:** take a snapshot (leads). The category's deduction is gone.

## 7. Rollback
- **Implemented change:** the requester or a lead moves it to *Rolled back* with the reason. A
  `waf_rule` change restores the previous rule mode.
- **Approved exception no longer justified:** close it with the reason, then
  `make accepted-risks` and commit.
- **Archived model:** the page has no unarchive button yet. A lead sets the status back with
  `PATCH /api/v1/threat-models/{id}` (`{"version": n, "status": "active"}`), which is audited.
  Permanent deletion cannot be undone; the audit log keeps only a summary.

## 8. Post-incident
- Record the decision and its reference on the incident, then close it.
- If the workflow was bypassed, add the bypass as a threat (T-GOV) with its control, and a test
  that would have caught it.
- Review the threat model at the end of every phase and whenever a trust boundary, data flow or
  role changes. Then run `make governance-catalogue`.
