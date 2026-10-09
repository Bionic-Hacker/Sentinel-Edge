# SentinelEdge developer entry points. `make help` lists targets.
SHELL := /bin/bash
.DEFAULT_GOAL := help
GITLEAKS_IMAGE := ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f

.PHONY: book prune-rate-limits help env env-check dev down logs clean install test test-backend test-frontend lint \
        typecheck security secrets-scan lock-backend precommit check verify-hardening \
        create-admin outbox verify-audit migrate smoke scan scan-test sbom dast scan-gate image-digests scan-import \
        governance-catalogue accepted-risks ai-check bedrock-credentials bedrock-credentials-clear \
        tf-check tf-init tf-plan tf-apply tf-destroy-plan tf-output tf-lock

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

prune-rate-limits: ## Delete rate-limit buckets idle for over a day
	docker compose exec api python -m app.cli prune-rate-limits

smoke: ## End-to-end smoke test of the running stack (auth, audit, API security, security operations)
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

book: ## Rebuild the engineering book PDF (docs/book/SentinelEdge-Engineering-Blueprint.pdf)
	python -m pip install -q --require-hashes -r docs/book/requirements.txt
	python docs/book/build.py

scan: ## Application security scans (SAST, SCA, secrets, IaC, containers, SBOM), then the gate
	./scripts/scan.sh

scan-test: ## Test the SentinelEdge Semgrep rules against their annotated examples
	docker run --rm -u "$$(id -u):$$(id -g)" -e HOME=/tmp -v "$$PWD:/src:ro" -w /src \
	  $$(grep -m1 -o 'semgrep/semgrep:[^}"]*' scripts/scan.sh) \
	  semgrep --metrics=off --disable-version-check --test scanning/semgrep

sbom: ## CycloneDX SBOMs for the API image, the web image and the source tree
	./scripts/scan.sh sbom

dast: ## ZAP baseline + authenticated API scan of the running local stack (make dev first), then the gate
	./scripts/scan.sh dast gate

scan-gate: ## Re-apply the gate to the existing reports (after editing accepted-findings.toml)
	./scripts/scan.sh gate

scan-import: ## Import reports/scan into vulnerability management (FROM=dir SOURCE=ci for a CI artifact)
	@test -d "$(or $(FROM),reports/scan)" || { echo "No reports at $(or $(FROM),reports/scan): run make scan first"; exit 2; }
	set -o pipefail; python3 scripts/scan-bundle.py "$(or $(FROM),reports/scan)" | docker compose exec -T api \
	  python -m app.cli import-scan --application "$(or $(APP),sentineledge)" --source "$(or $(SOURCE),local)" \
	  $(if $(COMMIT),--commit "$(COMMIT)",$(if $(FROM),,--commit "$$(git rev-parse HEAD)" --branch "$$(git rev-parse --abbrev-ref HEAD)")) \
	  --actor "$$(git config user.email || echo operator)"

accepted-risks: ## Regenerate scanning/accepted-findings.toml from the approved scan-finding exceptions (stack running)
	set -o pipefail; docker compose exec -T api python -m app.cli export-accepted-risks > scanning/accepted-findings.toml.new
	mv scanning/accepted-findings.toml.new scanning/accepted-findings.toml
	@echo "Regenerated scanning/accepted-findings.toml: review the diff and commit it."

governance-catalogue: ## Regenerate the governance catalogue after editing docs/threat-model.md or docs/security-controls.md
	python3 scripts/governance-catalogue.py

ai-check: ## Send one synthetic analysis to the configured AI provider and check the answer (stack running)
	docker compose exec -T api python -m app.cli ai-check

bedrock-credentials: ## Write short-lived AWS session credentials for Bedrock to .env.bedrock (AWS_PROFILE=, HOURS=)
	./scripts/bedrock-credentials.sh

bedrock-credentials-clear: ## Remove the Bedrock session credentials and reload the API without them
	rm -f .env.bedrock
	docker compose up -d api

image-digests: ## Check pinned image digests against their tags (UPDATE=1 rewrites stale pins)
	./scripts/image-digests.sh

# --- Terraform (Phase 3+). STACK is bootstrap, account or dev. Nothing is applied without a
# saved, reviewed plan; see docs/aws-setup.md. ---------------------------------------------
STACK ?=
tf-stack = $(if $(STACK),$(STACK),$(error Set STACK=bootstrap, account or dev))

tf-check: ## Terraform fmt, validate, module tests and TFLint (no AWS credentials needed)
	./scripts/tf-check.sh

tf-init: ## Initialise a stack against its remote state: make tf-init STACK=account
	./scripts/tf.sh $(tf-stack) init

tf-plan: ## Plan a stack and save the plan for review: make tf-plan STACK=account
	./scripts/tf.sh $(tf-stack) plan

tf-apply: ## Apply exactly the saved plan of a stack: make tf-apply STACK=account
	./scripts/tf.sh $(tf-stack) apply

tf-destroy-plan: ## Plan the destruction of a stack and save it for review: make tf-destroy-plan STACK=dev
	./scripts/tf.sh $(tf-stack) destroy-plan

tf-output: ## Show a stack's outputs: make tf-output STACK=bootstrap
	./scripts/tf.sh $(tf-stack) output

tf-lock: ## Record provider checksums for Linux, macOS and CI in a stack's lock file: make tf-lock STACK=account
	./scripts/tf.sh $(tf-stack) lock

precommit: ## Install git pre-commit hooks
	pre-commit install

check: lint typecheck test security ## Everything CI runs
