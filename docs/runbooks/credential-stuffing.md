# Runbook: Credential stuffing

- **Severity guidance:** SEV1 if COR-007 fired (a sign-in succeeded from the stuffing source) for
  an ADMIN or SECURITY_ENGINEER account; SEV2 if COR-007 fired for any other account; SEV3 for
  COR-001 alone (attempts, no success).
- **Owner role:** ANALYST (triage, investigation), SECURITY_ENGINEER (containment, closure)
- **Related threats / controls:** T-ID-01, T-ID-03, T-ID-10 · C-ID-04, C-ID-05, C-API-03,
  C-SO-04, C-SO-05
- **Last exercised:** 2026-10-07, attack simulator scenario "Credential stuffing" and `make smoke`

## 1. Detection

| Signal | Where |
|---|---|
| **COR-001 Credential stuffing**: 10+ failed sign-ins from one address against 3+ accounts in 10 minutes | Threats page, filter *Source: Detection rule*; HIGH, opens an incident |
| **COR-007 Sign-in from a credential-stuffing source**: a sign-in succeeded from that address | Threats page; HIGH, opens or joins the incident. **Treat as a compromised account** |
| COR-002 Sustained password guessing against one account | Threats page; usually a single targeted user rather than stuffing |
| `auth.account_locked` for several accounts in a short time | Audit logs |
| Rate-limit trips on `POST /api/v1/auth/login` | API Security Center: the login endpoint shows *elevated*; COR-005 if repeated |

Confirm it is real: open the incident's **Evidence** table. Stuffing shows many different
accounts (often ones that don't exist) from one source, with a steady cadence and a scripted user
agent. A user mistyping their own password produces failures against one account, which COR-001
deliberately ignores.

## 2. Triage (first 15 minutes)
1. Open the incident (Incidents → live view). Select **Move to Triaged**: as an analyst you
   become the owner.
2. Note the source address, the window, how many accounts were tried, and whether **COR-007**
   appears in the evidence (a success). If it does, follow the
   [compromised credential](compromised-credential.md) runbook for that account in parallel.
3. Set the severity per the guidance above (a lead changes it under **Edit details**).

## 3. Investigation
1. Threats page → *Source IP* = the address → every event it produced. Look for what followed a
   success: authorization denials (BOLA/BFLA probing), rate-limit trips, injection attempts.
2. Audit logs, filter `auth.login` and `auth.account_locked`: list the accounts targeted. Real
   accounts among them are the ones at risk.
3. For any account that signed in from the source: its sessions, actions and source IPs in the
   audit log after the sign-in.
4. Record findings as timeline notes. Notes are permanent and digest-protected; correct a note by
   adding another.

## 4. Containment
1. Account that signed in from the source (COR-007): Settings → Users → **Deactivate** (revokes
   every session at once). Do not delete it: its state is evidence.
2. Locked accounts unlock themselves after 15 minutes; leave them locked while the attack runs.
3. Per-IP sign-in limits (20 per 2 minutes) already slow the source. Blocking the address at the
   edge is a WAF IP-set change, made through Terraform (ADR-0008) once AWS WAF exists (Phase 5);
   until then, record the address in the incident for the change request.
4. Move the incident to **Containment** once no new failures arrive from the source.

## 5. Remediation
1. Affected users reset their passwords (Forgot your password?); privileged roles re-enroll MFA if
   it may be exposed.
2. Consider requiring MFA for more roles if a non-MFA account was taken over.
3. Move to **Remediation**, then **Validation**, recording what was changed.

## 6. Validation
- No new COR-001 or COR-007 detections for the source over the following window.
- `make verify-audit` reports the chain intact; the incident's **Evidence integrity** panel shows
  *Verified*.
- The deactivated accounts' old tokens return 401.

## 7. Rollback
Reactivate accounts once their owners have new credentials. Lift any edge block through the same
reviewed Terraform change that added it.

## 8. Post-incident
A lead closes the incident with resolution *Resolved* and a summary note (or *False positive*
for a load test or a misconfigured client). Record lessons learned; if a control failed, add a
regression test and update the threat model.
