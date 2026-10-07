# Runbook: Compromised credential

- **Severity guidance:** SEV1 if the account is ADMIN or SECURITY_ENGINEER, or if a refresh-token
  reuse alert fired; SEV2 for other roles with evidence of use; SEV3 for a suspected exposure with
  no evidence of use.
- **Owner role:** SECURITY_ENGINEER (investigation), ADMIN (containment)
- **Related threats / controls:** T-ID-01, T-ID-02, T-ID-03 · C-ID-02, C-ID-03, C-ID-05, C-AUD-01
- **Last exercised:** 2026-10-07, `make smoke` (refresh-token reuse, lockout)

## 1. Detection

| Signal | Where |
|---|---|
| `auth.refresh_token_reuse` (result `denied`) | Audit logs → Action filter. **Treat as confirmed theft**: a rotated token was replayed. |
| Burst of `auth.login` failures then `auth.account_locked` | Audit logs, filter by actor email |
| Successful `auth.login` from an unusual source IP or user agent | Audit log details; compare with the user's history |
| `authz.denied` from an account probing other users' records | Audit logs → `authz.denied`, resource `user` |
| User reports a password-reset email they didn't request | `auth.password_reset_requested` for that actor |

Confirm it is not a false positive: a reuse alert can also come from a user's two devices racing,
but the frontend serializes refresh across tabs, so treat it as theft unless the user can explain it.

## 2. Triage (first 15 minutes)
1. Identify the account and role. Privileged role → SEV1.
2. In the audit log, filter by the actor email for the last 24 hours. Note source IPs,
   correlation IDs and any `user.*` actions the account performed (role changes, invitations).
3. Open an incident (Phase 7 adds this to the app; until then, record it in the issue tracker).

## 3. Containment (lowest-risk action first)
1. **End every session for the account.** Settings → Users → **Deactivate**. This revokes all
   sessions immediately (access tokens stop working on the next request).
2. If the account must stay usable, reactivate it after step 4 instead of leaving it active now.
3. If the second factor may also be compromised: **Reset 2FA** (forces re-enrollment).
4. If the account is the attacker's way in to *other* accounts (it invited users or changed roles),
   review each `user.created` / `user.updated` record it produced and reverse them.

## 4. Remediation
1. Ask the user to reset their password through **Forgot your password?** (sessions are revoked
   again on reset). Admins never set passwords for users.
2. Reactivate the account once the user has a new password and, for privileged roles, MFA.
3. If many accounts are affected, rotate `SENTINEL_JWT_SIGNING_KEY` (signs **everyone** out).

## 5. Validation
- The old access token returns 401: `curl -H "Authorization: Bearer <old>" .../api/v1/auth/me`.
- `make verify-audit` reports the chain intact (the attacker didn't alter history).
- No further `auth.*` activity from the attacker's source IPs.

## 6. Rollback
Reactivating the account (Settings → Users) reverses containment. Password and MFA resets are
not reversible by design.

## 7. Post-incident
Record the timeline from the audit log (correlation IDs link audit records to API logs), update
the threat model if a new path was found, and add a regression test if a control failed.
