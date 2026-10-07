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
make env        # creates .env from .env.example with a random DB password (mode 600)
make dev        # builds and starts db, api, web
open http://localhost:8080
make precommit  # install git hooks (Gitleaks, Ruff, Bandit, ESLint)
```

`make env` never overwrites an existing `.env`. The Compose file refuses to start if
`POSTGRES_PASSWORD` is unset.

## Day-to-day

| Task | Command |
|---|---|
| All checks CI runs | `make check` |
| Backend tests | `make test-backend` |
| Frontend tests | `make test-frontend` |
| Hot-reload frontend against the API container | `cd frontend && npm run dev` (http://127.0.0.1:5173) |
| Follow logs | `make logs` |
| Reset everything including DB data | `make clean` |

## Exposure rules

- Ports are bound to `127.0.0.1` only. Do not change them to `0.0.0.0`; the local stack has no
  WAF, TLS, or (until Phase 2) authentication.
- The database has no published port and sits on an internal-only network. Use
  `docker compose exec db psql -U "$POSTGRES_USER" "$POSTGRES_DB"` if you need a shell.
- Use synthetic data only (spec §48).

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `POSTGRES_PASSWORD ... run make env` | No `.env` | `make env` |
| UI shows "The API could not be reached" | API container down | `docker compose ps`, then `make logs` |
| API returns 400 for every request | Host not in `SENTINEL_TRUSTED_HOSTS` | Add the host to `.env` and restart |
| Error shows a reference ID | Expected: errors are generic | Search API logs for that `correlation_id` |
