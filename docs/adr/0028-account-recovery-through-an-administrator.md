# ADR-0028: No email path: administrators issue temporary passwords

- **Status:** Accepted
- **Date:** 2026-10-13
- **Phase:** 5 (found in the Phase 4–5 deploy window)
- **Decided by:** Bionic-Hacker (project owner)
- **Supersedes:** the invitation-link and self-service reset parts of ADR-0003
- **Builds on:** ADR-0003 (authentication), ADR-0005 (audit log), ADR-0026 (the first administrator
  in AWS)

## Context
Since Phase 2, new users were invited with a one-time link and anyone could request a
password-reset link from the sign-in page. Neither link was ever emailed: both went to a local
outbox that only the operator could read (`make outbox`), and real delivery through Amazon SES was
left for a later, separately approved integration.

In the first AWS deploy window the gap became real: an administrator invited a user and no link
arrived, because in AWS nothing reads the outbox. Three ways forward were weighed: record it as a
known gap, add a task that copies the newest link to a secret, or send email through SES.

The owner chose a fourth: leave email out of the design altogether. Account access then has one
way in, through an administrator, which keeps it consistent and means a lost password, a lost
device or a compromised mailbox can never be turned into access without someone with authority
being contacted first.

## Decision

**No email dependency.** The platform sends no email and stores none. The outbox, the reset-link
tokens, the public "forgot password" and "reset password" endpoints, the reset page and
`make outbox` are removed. Migration `0015` drops their tables; the audit log keeps every past
invitation and reset.

**Creating a user.** An administrator enters email, name and role. The platform generates a
temporary password and returns it once, in the creation response; the administrator hands it over
through a channel they trust.

**A forgotten password.** The user contacts an administrator, who chooses **Reset password**. The
platform generates a new temporary password and returns it once; the user's current password stops
working and every session ends. Their two-factor setup is kept, so a privileged account still needs
its second factor. A lost authenticator remains a separate administrator action (Reset 2FA).

**Temporary passwords.**
- Generated, never chosen: four groups of five characters from a 31-symbol alphabet without
  look-alike characters (`k7m2x-p9qra-4tz8h-cw3ny`), about 99 bits.
- Shown once. Stored only as an Argon2id hash. Never logged, never in the audit log (which records
  that one was issued, by whom, for whom, and until when), never readable again through the API.
  Responses carry `Cache-Control: no-store`.
- Expire after `temporary_password_ttl_seconds` (72 hours). An expired one is refused with
  `temporary_password_expired`, which only someone who knows the password can see; it does not count
  towards lockout. The administrator issues a new one.
- Sign in only to the setup steps: the user must set their own password (and enroll MFA for
  privileged roles) before anything else, the same gate the first administrator goes through.
- A reset also clears an account lockout.
- An administrator cannot reset their own password this way; they change it in Settings.

The first administrator is unchanged (ADR-0026): `create-admin` writes a one-time password to a
Secrets Manager secret in AWS and prints it locally. It does not expire, because an expired first
administrator could not be recreated under the same address.

## Security impact
- Mitigates T-ID-11 (new): account recovery hijacked through a compromised mailbox or an abused
  self-service reset. There is no such path.
- T-ID-12 (new): a temporary password seen while it is handed over. Mitigated by expiry, forced
  replacement and MFA; the hand-over channel is the residual risk.
- T-ID-05 (enumeration): no public endpoint takes an email address any more except sign-in.
- C-ID-07 is redefined: account recovery through an administrator only. T-ID-09 now also cites it.
- The `account_recovery` rate-limit policy is removed with the endpoints it protected.

## Alternatives considered
- **Record the gap and keep the outbox.** Leaves a feature that silently does nothing in AWS.
- **An `outbox` task writing the newest link to a secret.** Works, but keeps a mail-shaped
  mechanism with no mail, and an extra operator step for every invitation.
- **Amazon SES.** Real delivery, but adds domain verification records, sandbox limits, IAM for
  sending, bounce handling, and a recovery channel (the mailbox) outside the platform's control.
- **Administrators type the temporary password.** Simpler, but people reuse and choose guessable
  passwords; a generated one is always strong and never known before it is shown.

## Consequences
- A user who forgets their password waits for an administrator. Accepted: the platform is
  operated by a small team, and it is the point of the decision.
- Settings → Users: **Create user** and **Reset password**, each showing the temporary password
  once with Copy and Done. The sign-in page tells users to ask an administrator.
- `make smoke` creates its users with temporary passwords (70 checks).
