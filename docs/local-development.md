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
open http://localhost:8080
make precommit  # install git hooks (Gitleaks, Ruff, Bandit, ESLint)
```

`make env` never overwrites an existing `.env`. `make dev` refuses to start with a `.env` that is
missing a secret the current phase needs, and tells you how to regenerate it.

Start-up order: `db` initialises and runs `db/bootstrap-roles.sh` on first start → `migrate` applies
Alembic migrations as `sentinel_migrator` and exits → `api` starts as `sentinel_app` → `web`.

## Upgrading from Phase 1

Phase 2 introduced separate database roles (ADR-0015). Roles are created only when the database is
first initialised, so the local database and `.env` must be recreated once. Local data is
synthetic, so nothing of value is lost.

```bash
make clean                 # stop the stack and delete the old local database volume
mv .env .env.phase1.bak    # keep the old file until the new stack is up, then delete it
make env
make dev
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
| UI shows "The API could not be reached" | API container down | `docker compose ps`, then `make logs` |
| API returns 400 for every request | Host not in `SENTINEL_TRUSTED_HOSTS` | Add the host to `.env` and restart |
| Error shows a reference ID | Expected: errors are generic | Search API logs for that `correlation_id` |
