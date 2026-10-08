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
make smoke          # 48-check end-to-end test of the running stack
```

`make smoke` creates its own uniquely named synthetic users and locks one of them on purpose. It
also replays a refresh token on purpose, sends one SQL injection probe, and runs two attack
simulations (switching the simulated WAF's SQL injection rules to count and back).

`make env` never overwrites an existing `.env`. `make dev` refuses to start with a `.env` that is
missing a secret the current phase needs, and tells you how to regenerate it.

Start-up order: `db` initialises and runs `db/bootstrap-roles.sh` on first start → `migrate` applies
Alembic migrations as `sentinel_migrator` and exits → `api` starts as `sentinel_app` → `web`.

## Upgrading from v0.3.0 (Phase 6) to v0.4.0 (Phase 7)

Your data is kept. `make dev` rebuilds the images and the `migrate` container applies the three
new migrations; nothing else is needed.

```bash
make dev
docker compose logs migrate | grep "Running upgrade"   # 0005 -> 0006 -> 0007 -> 0008 on first run
```

| Migration | Adds |
|---|---|
| `0006_security_events` | Append-only security events (the app role may INSERT and SELECT only) |
| `0007_incidents` | Incidents, the append-only timeline, and the write-once `incident_id` trigger on events |
| `0008_applications_and_simulator` | Application inventory (seeded with SentinelEdge itself), simulation runs, simulated WAF rule modes |

**Expect one live incident from your own testing.** On one machine every request comes from the
same address (the Docker gateway, or `127.0.0.1` outside Docker). `make smoke` deliberately replays
a refresh token, locks an account and sends a SQL injection probe, so the first run opens a
"Rotated refresh token replayed: likely token theft" incident for that address, and later runs
join it as more evidence. A sign-in after the deliberate failures can raise COR-007 and lift it to
critical. This is the detection pipeline working, not an attack. Work it through the workflow
(or close it as a false positive with a note) to practise; incidents are never deleted.

Simulated activity from the Automation page appears only in the **Simulated** view of the
dashboard, Threats and Incidents pages, under an amber banner, and never in the live view.

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
| Generate simulated attack activity | Automation page (admin or security engineer), or `POST /api/v1/simulator/runs` |

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
| A "likely token theft" or "credential-stuffing source" incident appears | `make smoke` triggers them on purpose from your own address | Expected; see "Upgrading from v0.3.0" |
| "This incident changed since you loaded it" | Someone (or another tab) changed it first | Select Reload, then repeat the action |
