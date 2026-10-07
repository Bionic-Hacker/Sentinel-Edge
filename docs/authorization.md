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

## Endpoint matrix (Phase 2)

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
| `PATCH /users/{id}`, `POST /users/{id}/mfa/reset` | | | ✓³ | | | | |
| `GET /audit-logs`, `GET /audit-logs/verify` | | | ✓ | ✓ | | | |

1. Same-origin only: requires an allowed `Origin` and the `X-SentinelEdge-CSRF` header.
2. Object-level check (OWASP API1): any other ID returns the same 404 as a non-existent one, and
   the attempt is audited as `authz.denied`.
3. An admin cannot demote, deactivate or reset MFA on themselves, and the last active admin can't
   be removed.

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
