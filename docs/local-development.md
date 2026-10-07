# Local development

Everything in this guide is **LOCAL** — it creates no AWS resources and costs nothing.

## Requirements

| Tool | Version | Used for |
|---|---|---|
| Docker + Compose v2 | current | Local stack |
| Python | 3.12+ | Backend tooling and tests |
| Node.js | 22 LTS+ | Frontend tooling and tests |
| GNU Make, OpenSSL | any | Entry points, password generation |
| pre-commit | current | Local security gates |
| Terraform ≥ 1.10, AWS CLI v2 | — | Not needed until Phase 3 |

## First run

```bash
make env        # creates .env from .env.example; every secret is random and distinct (mode 600)
make dev        # builds and starts db, migrate (one-shot), api, web
make create-admin EMAIL=you@example.com   # prints a one-time password, shown once
open http://localhost:8080                # sign in, set your password, enroll MFA
make precommit  # install git hooks (Gitleaks, Ruff, Bandit, ESLint)
```

There are no default credentials. The first sign-in forces a new password and, for the admin
role, two-factor enrollment with an authenticator app. Other users are invited from
Settings → Users; their invitation (and any password-reset email) lands in the local outbox:

```bash
make outbox         # show recent "emails" with their one-time links
make verify-audit   # check the audit log hash chain
make smoke          # 26-check end-to-end test of auth, authorization and auditing
```

`make smoke` creates its own uniquely named synthetic users and locks one of them on purpose.

`make env` never overwrites an existing `.env`. `make dev` refuses to start with a `.env` that is
missing a secret the current phase needs, and tells you how to regenerate it.

Start-up order: `db` initialises and runs `db/bootstrap-roles.sh` on first start → `migrate` applies
Alembic migrations as `sentinel_migrator` and exits → `api` starts as `sentinel_app` → `web`.

## Upgrading from v0.2.0 (Phase 2) to v0.3.0 (Phase 6)

Your data is kept: new migrations add tables to the existing database. The only change that
needs a step is the pinned Docker network for trusted client IPs (ADR-0017).

```bash
docker compose down        # removes containers and networks, KEEPS the database volume
make dev                   # rebuilds images, re-creates the network, applies migrations 0004-0005
```

If `make dev` fails, it now prints the likely cause and fix (`scripts/diagnose-startup.sh`).

## Upgrading from Phase 1

Phase 2 introduced separate database roles (ADR-0015) and authentication keys. Roles are created
only when the database is first initialised, so the local database and `.env` must be recreated
once. Local data is synthetic, so nothing of value is lost.

```bash
make clean                 # stop the stack and delete the old local database volume
mv .env .env.phase1.bak    # keep the old file until the new stack is up, then delete it
make env
make dev
make create-admin EMAIL=you@example.com
```

## Day-to-day

| Task | Command |
|---|---|
| All checks CI runs | `make check` |
| Verify container and network hardening (stack running) | `make verify-hardening` |
| Backend tests (starts a throwaway PostgreSQL, needs Docker) | `make test-backend` |
| Apply new migrations to the running stack | `docker compose run --rm migrate` |
| Frontend tests | `make test-frontend` |
| Hot-reload frontend against the API container | `cd frontend && npm run dev` (http://127.0.0.1:5173) |
| Follow logs | `make logs` |
| Reset everything including DB data | `make clean` |
| Delete idle rate-limit buckets | `make prune-rate-limits` |

## Exposure rules

- Ports are bound to `127.0.0.1` only. Do not change them to `0.0.0.0`; the local stack has no
  WAF, TLS, or (until Phase 2) authentication.
- The database has no published port and sits on an internal-only network. For a shell, use
  `docker compose exec db psql -U sentinel_admin sentineledge` (admin) or
  `docker compose exec db psql -h 127.0.0.1 -U sentinel_app sentineledge` (app role; password in `.env`).
- Use synthetic data only (spec §48).

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `POSTGRES_PASSWORD ... run make env` | No `.env` | `make env` |
| `Your .env is missing ...` | `.env` predates the current phase | See "Upgrading from Phase 1" |
| `api` never starts; `migrate` exited non-zero | Migration failed | `docker compose logs migrate` |
| Database tests skipped | Tests run without a test database | Use `make test-backend`, not bare `pytest` |
| Can't sign in after `make clean` | The database (and your account) was deleted | `make create-admin EMAIL=...` again |
| Sign-in loops back to the login page | Refresh cookie blocked | Use `http://localhost:8080` (not an IP) so the `__Host-` cookie is accepted |
| Lost your authenticator and recovery codes | — | Another admin uses Settings → Users → Reset 2FA; if you're the only admin, `make clean` and start over (local data is synthetic) |
| UI shows "The API could not be reached" | API container down | `docker compose ps`, then `make logs` |
| API returns 400 for every request | Host not in `SENTINEL_TRUSTED_HOSTS` | Add the host to `.env` and restart |
| Error shows a reference ID | Expected: errors are generic | Search API logs for that `correlation_id` |
