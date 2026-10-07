# ADR-0015: Separate database roles for migrations and runtime

- **Status:** Accepted — implemented in Phase 2
- **Date:** 2026-10-07
- **Phase:** 2 (local, CI), 4 (RDS)

## Context
If the API connects to PostgreSQL as the schema owner, any SQL injection or code-execution bug
in the API inherits the ability to drop tables, alter the audit log, or grant itself access to
anything. Spec §34 requires least privilege for the database; ADR-0005 depends on the runtime
role being unable to modify audit records.

## Decision
Three identities, each with one job:

| Identity | Can | Cannot | Used by |
|---|---|---|---|
| Admin (`POSTGRES_USER`, RDS master) | Create roles and the schema | — | `db/bootstrap-roles.sh`, once |
| `sentinel_migrator` | Own and change the `sentinel` schema | Create roles or databases; superuser; bypass RLS | The one-shot `migrate` container (Alembic) |
| `sentinel_app` | Exactly the per-table privileges migrations grant it | DDL of any kind; read `alembic_version`; create in `public` | The API |

- **One bootstrap script everywhere.** `db/bootstrap-roles.sh` runs at first start of the local
  `db` container, in CI against a service container, in `make test-backend` against a throwaway
  container, and (Phase 4) as a one-off task against RDS. The privilege model can't drift
  between environments.
- **Explicit grants, no default privileges.** Each migration that creates a table grants the app
  role only what that table needs. `ALTER DEFAULT PRIVILEGES` is deliberately not used: it would
  silently hand every future table full read/write access.
- **A privilege-matrix test** compares the app role's actual grants with a hand-written expected
  table. Over-granting fails CI.
- **Secrets scoped per container.** The API container never receives the migrator or admin
  password; the `migrate` container never receives the app password.
- **Resource limits on the app role:** `statement_timeout = 15s`,
  `idle_in_transaction_session_timeout = 30s`.
- **TLS:** deployed environments must use `sslmode` `verify-ca` or `verify-full` (config
  validation refuses to start otherwise).

## Security impact
- An injection flaw in the API cannot alter schema, read migration state, or modify audit records
  (T-DB-03, T-AUD-01). Control C-DB-01.
- Credential theft from the API container exposes only the runtime role (T-DB-02).
- Unverified database TLS is impossible to deploy by accident (T-DB-04). Control C-DB-03.

## Alternatives considered
- **Single application role** — simplest, rejected for the reasons above.
- **Default privileges** — convenient, rejected because they grant by accident.
- **Row-level security** — not needed yet; reconsidered if multi-tenant data arrives.

## Consequences
- Upgrading from Phase 1 needs a fresh local database and `.env` (`docs/local-development.md`).
- On RDS (PostgreSQL 16+), the master user must be able to `SET ROLE` to `sentinel_migrator` to
  transfer schema ownership; Phase 4 grants that membership explicitly before bootstrap.
