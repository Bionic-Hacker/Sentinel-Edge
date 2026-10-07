# SentinelEdge developer entry points. `make help` lists targets.
SHELL := /bin/bash
.DEFAULT_GOAL := help
GITLEAKS_IMAGE := ghcr.io/gitleaks/gitleaks:v8.30.1

.PHONY: help env dev down logs clean install test test-backend test-frontend lint typecheck \
        security secrets-scan lock-backend precommit check verify-hardening

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-16s %s\n", $$1, $$2}'

env: ## Create .env from .env.example with a generated local DB password (never overwrites)
	@test ! -f .env || { echo ".env already exists; leaving it untouched"; exit 0; }; \
	pw=$$(openssl rand -base64 32 | tr -dc 'A-Za-z0-9' | head -c 32); \
	sed "s/CHANGE_ME_local_only_password/$$pw/" .env.example > .env; chmod 600 .env; \
	echo "Created .env (mode 600) with a random local database password"

dev: env ## Build and start the local stack (web :8080, api :8000)
	docker compose up --build -d
	@echo "SentinelEdge:  http://localhost:8080   API health: http://localhost:8000/api/v1/health"

down: ## Stop the local stack
	docker compose down

verify-hardening: ## Check container, network and HTTP hardening of the running stack
	./scripts/verify-hardening.sh

logs: ## Follow structured logs
	docker compose logs -f api web

clean: ## Stop the stack and delete local volumes (destroys local DB data)
	docker compose down -v

install: ## Install backend and frontend dependencies for local tooling
	cd backend && python -m pip install --require-hashes -r requirements.txt -r requirements-dev.txt
	cd frontend && npm ci --ignore-scripts

test: test-backend test-frontend ## Run all tests

test-backend: ## Backend unit, API and security tests with coverage gate
	cd backend && python -m pytest

test-frontend: ## Frontend unit and component tests
	cd frontend && npm test

lint: ## Lint backend and frontend
	cd backend && ruff check . && ruff format --check .
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
