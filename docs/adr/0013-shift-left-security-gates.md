# ADR-0013: Security gates from Phase 1

- **Status:** Accepted
- **Date:** 2026-10-06

## Context
The spec places full scanning in Phase 8 and the pipeline in Phase 11. A security project that
runs without secret scanning or SAST for seven phases contradicts its own story.

## Decision
Phase 1 ships a minimal but real gate set, locally (pre-commit) and in CI:
Gitleaks (full history), Ruff with the `S` (bandit) rule family, Bandit, mypy strict,
pip-audit, npm audit, ESLint rules banning `dangerouslySetInnerHTML`, `innerHTML`, `eval`, and web
storage, and a 90% backend coverage floor. Phases 8 and 11 add Semgrep, Checkov, Trivy, Syft,
ZAP, and Terraform gates.

## Consequences
Every later phase inherits enforcement rather than adding it retroactively.
