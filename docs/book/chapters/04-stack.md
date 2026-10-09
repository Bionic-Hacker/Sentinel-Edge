# Technology Stack and Rationale

<p class="lead">Each technology was chosen for a reason that can be explained in a sentence, and a rejected alternative is recorded next to it. Versions are pinned: Python dependencies by hash, npm by lockfile, CI actions by commit SHA.</p>

## Backend

| Technology | Version | Why it was chosen | Alternative considered |
|---|---|---|---|
| Python | 3.12 | Mature security tooling (Bandit, pip-audit, mypy) and a strong typing story | — |
| FastAPI | 0.142 | Dependency injection makes authorization a declared, testable property of every route | Flask (authorization by convention, harder to sweep) |
| Pydantic | v2 | `extra="forbid"` request models and explicit response models enforce API3 structurally | Hand-written validation |
| SQLAlchemy | 2.1 | Typed ORM; parameterized queries by construction | Raw SQL |
| Alembic | 1.20 | Versioned migrations with an `alembic check` drift gate in CI | Auto-create tables (no history, no grants) |
| psycopg | 3 | Modern PostgreSQL driver with TLS verification support | psycopg2 |
| Uvicorn | 0.54 | ASGI server; proxy-header handling disabled so the app makes the only trust decision | — |
| argon2-cffi | 25.1 | Argon2id: memory-hard, the current OWASP recommendation | bcrypt, PBKDF2 |
| PyJWT | 2.15 | Algorithm pinned server-side; `aud`, `iss` and `exp` required | — |
| pyotp + cryptography | — | TOTP MFA; secrets Fernet-encrypted with a key outside the database | SMS (SIM-swap risk) |

## Database

**PostgreSQL 17** (local container, RDS on AWS). It does more than store data here. Its `INSERT … ON CONFLICT` makes the rate limiter atomic across API instances without Redis. Its advisory locks serialize the audit hash chain. Its grants and triggers enforce append-only audit history. Three roles separate duties: an admin that bootstraps, `sentinel_migrator` that owns the schema, and `sentinel_app` with only per-table grants (ADR-0015).

:::why Why not Redis or ElastiCache for rate limiting?
ElastiCache would add roughly $12 or more per month and another service to secure. PostgreSQL's single-statement upsert gives a correct shared counter at portfolio scale. The cost is one database write per limited request, which is recorded as a known consequence and scheduled for review in Phase 12.
:::

## Frontend

| Technology | Version | Why |
|---|---|---|
| React | 19 | Escapes output by default; component model fits an enterprise console |
| TypeScript | 6, strict + `exactOptionalPropertyTypes` | Response shapes are validated and typed end to end |
| Vite | 8 | Fast builds with hashed asset names, which enables `immutable` caching |
| Tailwind CSS | 4 | Styles compile to a static stylesheet, so CSP can forbid inline styles |
| Vitest + Testing Library | 5 | Behavior-level UI tests, including authorization-aware rendering |
| ESLint + jsx-a11y | 9 | Security rules ban `dangerouslySetInnerHTML`, `innerHTML`, `eval` and web storage; accessibility rules are a quality gate |
| nginx-unprivileged | — | Serves the SPA as non-root with strict headers; local stand-in for CloudFront |

## Infrastructure and delivery

| Technology | Role | Phase |
|---|---|---|
| Docker Compose | Local topology with hardened containers and isolated networks | 1 |
| GitHub Actions | CI gates, read-only token, SHA-pinned actions | 1 (baseline), 8, 11 |
| Gitleaks, Ruff (S rules), Bandit, mypy, pip-audit, npm audit | Shift-left gates in pre-commit and CI | 1 |
| Semgrep, Checkov, Trivy, Syft, OWASP ZAP | Full scanning, SBOMs and authenticated DAST, each in a digest-pinned image | 8 ✓ |
| Terraform ≥ 1.10 | All AWS infrastructure; S3 state with native locking | 3 |
| AWS: CloudFront, WAF, ACM, Route 53, ECS Fargate, ALB, RDS, Secrets Manager, KMS, CloudWatch, CloudTrail | Production architecture | 3–5 |
| Amazon Bedrock | AI analysis (Nova Micro, Converse API via boto3); session credentials locally, IAM task role when deployed | 9 ✓ |
| GitHub OIDC | No long-lived AWS keys in CI | 11 |

## Development environment

The project is developed on Garuda Linux (Arch-based) with the fish shell. All project entry points are `make` targets, so they behave the same in any shell. The few commands that differ in fish are noted in Part IV, for example `source .venv/bin/activate.fish` and `read -s` for a token prompt. Python tooling uses a `uv`-managed 3.12 virtual environment that matches CI.
