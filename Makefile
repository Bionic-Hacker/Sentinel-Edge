# SentinelEdge developer entry points. `make help` lists targets.
SHELL := /bin/bash
.DEFAULT_GOAL := help
GITLEAKS_IMAGE := ghcr.io/gitleaks/gitleaks:v8.30.1

.PHONY: help env env-check dev down logs clean install test test-backend test-frontend lint \
        typecheck security secrets-scan lock-backend precommit check verify-hardening \
        create-admin outbox verify-audit migrate smoke

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-16s %s\n", $$1, $$2}'

env: ## Create .env from .env.example, each CHANGE_ME replaced by its own random secret
	@test ! -f .env || { echo ".env already exists; leaving it untouched"; exit 0; }; \
	umask 077; cp .env.example .env; \
	while grep -q 'CHANGE_ME_FERNET_[A-Za-z0-9_]*' .env; do \
	  sed -i "0,/CHANGE_ME_FERNET_[A-Za-z0-9_]*/s//$$(openssl rand -base64 32 | tr '+/' '-_')/" .env; \
	done; \
	while grep -q 'CHANGE_ME_[A-Za-z0-9_]*' .env; do \
	  sed -i "0,/CHANGE_ME_[A-Za-z0-9_]*/s//$$(openssl rand -hex 24)/" .env; \
	done; \
	echo "Created .env (mode 600) with random local secrets"

env-check: # Refuse to start with a .env from an older phase (missing required secrets)
	@for key in $$(grep -o '^[A-Z_]*=CHANGE_ME' .env.example | cut -d= -f1); do \
	  grep -q "^$$key=" .env || { \
	    echo "Your .env is missing $$key (it predates the current phase)."; \
	    echo "Regenerate it:  make clean && mv .env .env.bak && make env && make dev"; \
	    exit 1; }; \
	done

dev: env env-check ## Build and start the local stack (web :8080, api :8000)
	@docker compose up --build -d || { ./scripts/diagnose-startup.sh; exit 1; }
	@echo "SentinelEdge:  http://localhost:8080   API health: http://localhost:8000/api/v1/health"

down: ## Stop the local stack
	docker compose down

verify-hardening: ## Check container, network and HTTP hardening of the running stack
	./scripts/verify-hardening.sh

create-admin: ## Create an ADMIN with a one-time password: make create-admin EMAIL=you@example.com
	@test -n "$(EMAIL)" || { echo "Usage: make create-admin EMAIL=you@example.com"; exit 2; }
	docker compose exec api python -m app.cli create-admin --email "$(EMAIL)"

outbox: ## Show the local email outbox (password-reset links)
	docker compose exec api python -m app.cli outbox

verify-audit: ## Verify the audit log hash chain
	docker compose exec api python -m app.cli verify-audit

smoke: ## End-to-end auth/authz/audit smoke test against the running stack
	backend/.venv/bin/python scripts/smoke-auth.py 2>/dev/null || python scripts/smoke-auth.py

migrate: ## Apply new database migrations to the running stack
	docker compose run --rm migrate

logs: ## Follow structured logs
	docker compose logs -f migrate api web

clean: ## Stop the stack and delete local volumes (destroys local DB data)
	docker compose down -v

install: ## Install backend and frontend dependencies for local tooling
	cd backend && python -m pip install --require-hashes -r requirements.txt -r requirements-dev.txt
	cd frontend && npm ci --ignore-scripts

test: test-backend test-frontend ## Run all tests

test-backend: ## Backend tests against a throwaway PostgreSQL (needs Docker), with coverage gate
	cd backend && ../scripts/with-test-db.sh sh -c 'python -m pytest && alembic upgrade head && alembic check'

test-frontend: ## Frontend unit and component tests
	cd frontend && npm test

lint: ## Lint backend and frontend
	cd backend && ruff check . ../scripts && ruff format --check . ../scripts
	cd frontend && npm run lint

typecheck: ## Static type checks
	cd backend && mypy app
	cd frontend && npm run typecheck

security: secrets-scan ## Local security checks (SAST + SCA + secrets)
	cd backend && bandit -q -c pyproject.toml -r app
	cd backend && pip-audit -r requirements.txt --require-hashes
	cd frontend && npm audit --audit-level=high

secrets-scan: ## Scan the working tree and git history for secrets
	docker run --rm -v "$$PWD:/repo:ro" $(GITLEAKS_IMAGE) git /repo --config /repo/.gitleaks.toml --redact --verbose

lock-backend: ## Re-resolve hash-pinned backend lock files
	cd backend && pip-compile -q --generate-hashes --strip-extras --allow-unsafe -o requirements.txt requirements.in
	cd backend && pip-compile -q --generate-hashes --strip-extras --allow-unsafe -o requirements-dev.txt requirements-dev.in

precommit: ## Install git pre-commit hooks
	pre-commit install

check: lint typecheck test security ## Everything CI runs
