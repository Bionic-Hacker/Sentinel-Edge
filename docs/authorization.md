# Authorization

Who can do what, and how that is enforced. The table below is the policy; the automated test
`backend/tests/security/test_authz_matrix.py` holds the same table and fails CI if the code drifts
from it in either direction.

## Roles (spec §28)

| Role | Purpose | MFA required |
|---|---|---|
| ADMIN | Platform administration, user and role management | Yes |
| SECURITY_ENGINEER | Security configuration and investigations | Yes |
| DEVELOPER | Application, API and vulnerability information | No |
| ANALYST | Incident investigation | No |
| VIEWER | Read-only | No |

## Endpoint matrix (Phase 9)

✓ = allowed. "Setup" = any signed-in user, even before finishing forced setup.

| Endpoint | Public | Setup | ADMIN | SEC_ENG | DEVELOPER | ANALYST | VIEWER |
|---|---|---|---|---|---|---|---|
| `GET /health`, `GET /ready` | ✓ | | | | | | |
| `POST /auth/login`, `/auth/mfa/verify`, `/auth/refresh` | ✓¹ | | | | | | |
| `POST /auth/password/forgot`, `/auth/password/reset` | ✓¹ | | | | | | |
| `GET /auth/me`, `POST /auth/logout` | | ✓ | | | | | |
| `POST /auth/password/change`, `/auth/mfa/enroll[/confirm]` | | ✓ | | | | | |
| `GET /platform/capabilities` | | | ✓ | ✓ | ✓ | ✓ | ✓ |
| `GET /users/{id}` | | | ✓ any | ✓ own² | ✓ own² | ✓ own² | ✓ own² |
| `GET /users`, `POST /users` | | | ✓ | | | | |
| `PATCH /users/{id}`, `POST /users/{id}/mfa/reset`, `DELETE /users/{id}` | | | ✓³ | | | | |
| `GET /audit-logs`, `GET /audit-logs/verify` | | | ✓ | ✓ | | | |
| `GET /api-security/inventory`, `GET /api-security/owasp` | | | ✓ | ✓ | ✓ | | |
| `GET /security-events`, `GET /security-events/{id}` | | | ✓ | ✓ | | ✓ | ✓ |
| `GET /security/overview` | | | ✓ | ✓ | | ✓ | ✓ |
| `GET /incidents`, `GET /incidents/{id}` | | | ✓ | ✓ | | ✓ | ✓ |
| `POST /incidents`, `GET /incidents/assignees` | | | ✓ | ✓ | | ✓ | |
| `PATCH /incidents/{id}`, `POST /incidents/{id}/transitions`, `/assignment`, `/notes`, `/events` | | | ✓ | ✓ | | ✓⁴ | |
| `GET /applications`, `GET /applications/{id}` | | | ✓ | ✓ | ✓ own⁵ | ✓ | ✓ |
| `POST /applications`, `PATCH /applications/{id}`, `GET /applications/owners` | | | ✓ | ✓ | | | |
| `GET /simulator/scenarios`, `/simulator/runs`, `/simulator/waf-rules` | | | ✓ | ✓ | | ✓ | |
| `POST /simulator/runs`, `PUT /simulator/waf-rules/{rule_id}` | | | ✓ | ✓ | | | |
| `GET /vulnerabilities`, `/vulnerabilities/overview`, `/vulnerabilities/{id}` | | | ✓ | ✓ | ✓ own⁵ | ✓ | ✓ |
| `GET /scans`, `/scans/{id}`, `/sboms`, `/sboms/{id}`, `/sboms/{id}/document` | | | ✓ | ✓ | ✓ own⁵ | ✓ | ✓ |
| `POST /vulnerabilities/{id}/status` | | | ✓ | ✓ | ✓ own⁶ | | |
| `POST /vulnerabilities/{id}/acceptances`, `.../acceptances/{acceptance_id}/revoke` | | | ✓ | ✓ | | | |
| `GET /governance/controls`, `/governance/requirements`, `/governance/posture` | | | ✓ | ✓ | ✓ | ✓ | ✓ |
| `POST /governance/posture/snapshots` | | | ✓ | ✓ | | | |
| `GET /threat-models`, `/threat-models/{id}` | | | ✓ | ✓ | ✓ own⁵ | ✓ | ✓ |
| `POST /threat-models`, `PATCH /threat-models/{id}`, `POST .../elements`, `PATCH .../elements/{element_id}`, `POST .../threats`, `PATCH .../threats/{threat_id}` | | | ✓⁷ | ✓⁷ | | | |
| `POST /threat-models/{id}/archive` | | | ✓⁷ | ✓⁷ | ✓ own⁵ | | |
| `DELETE /threat-models/{id}` | | | ✓⁷ | ✓⁷ | | | |
| `GET /exceptions`, `/exceptions/{id}`, `/change-requests`, `/change-requests/{id}` | | | ✓ | ✓ | ✓ own⁵ | ✓ | ✓ |
| `POST /exceptions`, `/change-requests` | | | ✓ | ✓ | ✓ own⁵ | | |
| `POST /exceptions/{id}/decision` | | | ✓⁸ | ✓⁸ | | | |
| `POST /exceptions/{id}/close`, `/change-requests/{id}/transition` | | | ✓⁸ | ✓⁸ | ✓ own⁸ | | |
| `GET /ai/status` | | | ✓ | ✓ | ✓ | ✓ | ✓ |
| `POST /ai/analyses` | | | ✓⁹ | ✓⁹ | ✓ own⁹ | ✓⁹ | |
| `GET /ai/analyses`, `/ai/analyses/{id}`, `/ai/proposals` | | | ✓ | ✓ | ✓ own⁵ | ✓ | ✓ |
| `POST /ai/proposals/{id}/decision` | | | ✓¹⁰ | ✓¹⁰ | | | |

1. Same-origin only: requires an allowed `Origin` and the `X-SentinelEdge-CSRF` header.
2. Object-level check (OWASP API1): any other ID returns the same 404 as a non-existent one, and
   the attempt is audited as `authz.denied`.
3. An admin cannot demote, deactivate, delete or reset MFA on themselves, and the last active
   admin can't be removed.
4. Object-level workflow rules apply on top of the role check; see the incident matrix below.
5. Developers see only the applications they own, and only those applications' findings, scans,
   SBOMs, threat models, exceptions, change requests, and AI analyses and proposals about them. Any
   other ID returns 404, audited as
   `authz.denied`.
6. Status rules apply on top of the role check; see the finding matrix below.
7. Not on SentinelEdge's own threat model, which is maintained as code (409 `maintained_as_code`).
8. Separation of duties and workflow rules apply on top of the role check; see the governance
   matrix below.
9. The subject must be visible to the caller on its own page; developers analyse only findings
   and threat models of their own applications. Never a VIEWER: the DAST scanner is one, so a scan
   cannot spend AI tokens. Daily limits apply before any model call (429).
10. Approval runs the proposed action as the approving lead, through its own workflow; a
    proposal from a high prompt-risk input needs a written reason; rejection always does.

## Incident permission matrix (Phase 7)

The role check above admits investigators to the write endpoints; the incident service then
decides what each person may do to each incident. Every incident response carries the result as
`available_moves` and `permissions`, and the UI renders only those (ADR-0018).

| Action | Leads (ADMIN, SECURITY_ENGINEER) | ANALYST | VIEWER |
|---|---|---|---|
| Read incidents, timeline and evidence | ✓ | ✓ | ✓ |
| Open an incident (manually or from an event) | ✓ | ✓ (becomes the owner) | |
| Triage an unassigned DETECTED incident | ✓ | ✓ (assigned to them) | |
| Advance the workflow one step, or fail validation | ✓ | ✓ own | |
| Close (with a resolution) or close as not an incident | ✓ | | |
| Reopen a closed incident | ✓ | | |
| Edit title, summary, remediation | ✓ | ✓ own | |
| Change severity | ✓ | | |
| Assign to someone else, or unassign | ✓ | | |
| Take an unassigned open incident | (assign it instead) | ✓ | |
| Add a note | ✓ | ✓ | |
| Link more events as evidence | ✓ | ✓ own | |

None of the write actions apply to a closed incident except reopening (leads) and adding notes.
Moves that end or reverse work need a note (close, close as not an incident, validation failed,
reopen); closing needs a resolution. Every write names the `version` it read and gets 409
`stale_version` if someone else changed the incident first. Notes, assignments and status changes
are timeline entries, committed to the audit chain and never edited.

## Finding permission matrix (Phase 8)

Every finding response carries `allowed_statuses`, `can_accept_risk` and `can_revoke_acceptance`,
computed by the server; the UI renders only those (ADR-0021).

| Action | Leads (ADMIN, SECURITY_ENGINEER) | DEVELOPER (own applications) | ANALYST, VIEWER |
|---|---|---|---|
| Read findings, scans and SBOMs; download an SBOM | ✓ | ✓ | ✓ |
| Open ↔ in progress | ✓ | ✓ | |
| Mark a false positive, or reopen one (note required) | ✓ | | |
| Accept a risk (within the severity's limit), revoke an acceptance | ✓ | | |
| Mark fixed | Nobody: only a scan that no longer reports the finding | | |

Every write names the `version` it read (409 `stale_version` otherwise) and is audited
(`vulnerability.status_changed`, `vulnerability.risk_accepted`, `vulnerability.acceptance_revoked`).
Scans are imported only through the CLI inside the API container (`make scan-import`); there is no
import endpoint. The authenticated DAST scan signs in as `dast-scanner@example.com`, a VIEWER,
through a session the CLI issues for one scan and revokes afterwards.

## Governance permission matrix (Phase 10)

Every threat model, exception and change request response carries `permissions` (and, for change
requests, `available_moves`), computed by the server; the UI renders only those (ADR-0022,
ADR-0023). "Requester" is whoever raised the record.

| Action | Leads (ADMIN, SECURITY_ENGINEER) | DEVELOPER (own applications) | ANALYST, VIEWER |
|---|---|---|---|
| Read the control catalogue, requirements, posture, models, exceptions, changes | ✓ | ✓ | ✓ |
| Take a posture snapshot | ✓ | | |
| Create or edit an application threat model, its elements and threats | ✓ | | |
| Archive an application threat model | ✓ | ✓ | |
| Delete an application threat model permanently | ✓ | | |
| Change SentinelEdge's own threat model | Nobody: a reviewed pull request to `docs/threat-model.md` | | |
| Request an exception, submit a change request | ✓ | ✓ | |
| Approve or reject an exception or change request | ✓, never their own | | |
| Withdraw or close an exception (reason required) | ✓ | ✓ requester | |
| Cancel a submitted change, implement an approved one, roll back an implemented one | ✓ | ✓ requester | |
| Validate an implemented change | ✓ | | |

Self-approval is refused with 409 `separation_of_duties` by the service and again by a database
CHECK. Decisions are final (database triggers), and the app role cannot delete exceptions or
change requests. Every write names the `version` it read (409 `stale_version` otherwise) and is
audited (`threat_model.*`, `exception.*`, `change_request.*`, `posture.snapshot_taken`). A
permanent model deletion records a summary of what was removed. The VIEWER role stays read-only
everywhere because the authenticated DAST scanner signs in as a VIEWER.

## How it is enforced

- **Declared on every route.** Each route depends on exactly one of `public_endpoint`,
  `authenticated_setup` or `require_roles(...)` (`backend/app/core/authz.py`). A route with none
  fails the matrix test.
- **Verified by a sweep.** The same test calls every protected route anonymously (expects 401) and
  as every role (expects 403 exactly where the table says no). A mutation check — weakening one
  route — fails three tests.
- **Server-side only.** The UI hides what a role can't use, for usability; it is never the control.
- **Fresh on every request.** The role and session state are read from the database per request,
  so a role change or deactivation applies immediately.
- **Audited.** Every 403 for a role mismatch and every BOLA attempt writes an `authz.denied` record.

## Deactivating versus deleting a user

| | Deactivate | Delete (trash icon) |
|---|---|---|
| Reversible | Yes: Reactivate | No |
| Sessions | Revoked at once | Removed at once |
| Account, password, 2FA, recovery codes, pending links | Kept | Removed |
| Email can be invited again | No (still in use) | Yes, as a new account with a new ID |
| Audit history | Kept | Kept: records hold the actor's ID and email as plain values, so the hash chain is unaffected (ADR-0005) |
| Audit record | `user.updated` | `user.deleted`, with the email, name and role at deletion |

Prefer deactivation during an incident, because the account and its state stay available for
investigation (`docs/runbooks/compromised-credential.md`). Delete accounts that should not exist:
a mistaken invite, or a departed user once any investigation is closed. The UI asks for explicit
confirmation in a warning dialog whose default action is Cancel.

The app database role gained `DELETE` on `users`, `auth_sessions`, `refresh_tokens` and
`password_reset_tokens` for this (migration `0003_user_deletion`). It still has no `DELETE`,
`UPDATE` or `TRUNCATE` on `audit_log`, and the privilege-matrix test pins the full set.

## Rate limits

Every endpoint also has a rate limit, keyed by client IP before authentication or by account
after it. The full policy table is in [ADR-0017](adr/0017-rate-limiting-and-client-ip.md); the
live values per endpoint are in the API Security Center (`/apis`).
