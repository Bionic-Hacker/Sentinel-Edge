# Testing and Evidence

<p class="lead">The project's working rule is that a control without a failing-attack test is a claim, not a control. This chapter shows how the test suite is organized and what each layer proves.</p>

## The layers

| Layer | Count (v0.4.0) | Runs against | Proves |
|---|---|---|---|
| Backend unit | part of 668 | Pure functions | Config refusals, logging redaction, token and password primitives, egress guard, capability rules, HTTP attack rules and their timing |
| Backend API and integration | part of 668 | **Real PostgreSQL** (throwaway container, real roles) | Auth flows, lockout, MFA, sessions, audit chain, grants, rate limiting under concurrency, security events, correlation, incident workflow and integrity, dashboard, applications, simulator |
| Backend security sweeps | part of 668 | The live route table | Every route declares access; every role is checked; every body forbids extras; every JSON route has a response model |
| Frontend | 75 | jsdom + mocked API | Token stays in memory; refresh is single-flight; client refuses cross-origin; role-aware rendering; response validation; pages render the server's permissions; attack snippets render as text |
| Smoke | 48 checks | The running Docker stack through nginx | The whole user journey, end to end, including live detection and the simulated WAF |
| Hardening | 17 checks | Running containers and networks | Non-root, read-only, no capabilities, isolated database, localhost binding, headers |

Backend coverage is 98.6%, against a CI floor of 90%. Database tests deliberately do **not** use SQLite or mocks. The grants, triggers, advisory locks and upsert semantics being tested exist only in PostgreSQL, and the test database is bootstrapped by the same role script used everywhere else.

## Negative tests that matter

- **Forged tokens.** `alg: none`, algorithm substitution, wrong key, wrong audience, wrong issuer, wrong token type and expired tokens are all rejected.
- **Replay.** A rotated refresh token presented again revokes the session. A TOTP code is accepted once.
- **Enumeration.** Unknown, inactive and locked accounts give identical responses after identical work.
- **CSRF.** Cookie-bearing endpoints reject a missing or foreign `Origin` and a missing custom header.
- **BOLA.** Another user's record returns the same 404 as a non-existent one, and the attempt is audited.
- **Audit tampering.** The app role cannot update, delete or truncate. A trigger blocks even the table owner. A modified record is detected at its exact position.
- **Over-privilege.** The app role's grants must equal a hand-written matrix, so an extra grant fails.
- **Rate limiting.** Forty concurrent threads never overspend a bucket. A flood is audited once. A database outage yields `503`, never unlimited access.
- **Spoofing.** `X-Forwarded-For` from an untrusted peer is ignored. Prepended entries are skipped. Malformed hops stop the walk.
- **SSRF.** Loopback, private, link-local and metadata addresses are refused, including IPv4-mapped and 6to4 forms.
- **Error leakage.** No stack traces, paths, secrets or reflected input appear in any error.
- **Detection.** Each HTTP rule fires on its attack and stays quiet on ordinary traffic; double-encoded payloads are decoded; sensitive fields are never quoted.
- **ReDoS.** Every detection pattern is timed against adversarial input and must stay linear.
- **Exactly once.** Thirty threads failing sign-ins at once raise one detection and one incident.
- **Provenance.** Simulated events never raise or join a real detection or incident, and never appear in the live view.
- **Evidence tampering.** Editing or deleting a timeline entry as the table owner is reported on the next read; the app role cannot rewrite incident records; an event's incident link cannot be changed once set.
- **Workflow bypass.** Analysts cannot work someone else's incident, close it, or change its severity; viewers cannot write; a stale write is refused with 409.
- **Simulator abuse.** A run request carrying a target URL or address is rejected.
- **Stored XSS.** A `<script>` snippet in event evidence renders as text in the browser.

## Tests that test the tests

Several tests exist to stop the evidence going stale:

- The authorization matrix was mutated on purpose (one route weakened), and three tests failed. This proves the sweep has teeth.
- The OWASP coverage endpoint cites test names, and a test fails if any cited test no longer exists.
- The API inventory's access descriptions are compared with the independently written authorization matrix.
- The capability register's guard tests stop a SIMULATED or future-phase capability being marked as a real, implemented AWS control.
- Every inspection exclusion must name a real route and a real request field, and every correlation rule ID must be unique and documented.

## Continuous integration

GitHub Actions runs three jobs on every push and pull request: secret scanning (Gitleaks over full history); the backend (Ruff, mypy strict, Bandit, pip-audit, the role bootstrap, tests with the coverage gate, and an `alembic check` schema-drift gate); and the frontend (`npm ci --ignore-scripts`, ESLint, TypeScript, Vitest, production build, `npm audit`). The token is read-only, and every action is pinned by SHA.
