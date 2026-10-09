# Testing and Evidence

<p class="lead">The project's working rule is that a control without a failing-attack test is a claim, not a control. This chapter shows how the test suite is organized and what each layer proves.</p>

## The layers

| Layer | Count (v0.7.0) | Runs against | Proves |
|---|---|---|---|
| Backend unit | part of 991 | Pure functions | Config refusals, logging redaction, token and password primitives, egress guard, capability rules, HTTP attack rules and their timing, report parsers, backend/SPA enumeration parity, the governance catalogue against its documents, posture categories, AI guardrails and the output contract, Bedrock calls (stubbed) |
| Backend API and integration | part of 991 | **Real PostgreSQL** (throwaway container, real roles) | Auth flows, lockout, MFA, sessions, audit chain, grants, rate limiting under concurrency, security events, correlation, incident workflow and integrity, dashboard, applications, simulator, scan gate, scan import, finding lifecycle, risk acceptance, SBOMs, catalogue load, threat models, exceptions, change requests, posture, AI analyses, compromised-model answers, proposals and their approval |
| Backend security sweeps | part of 991 | The live route table | Every route declares access; every role is checked; every body forbids extras; every JSON route has a response model |
| Frontend | 115 | jsdom + mocked API | Token stays in memory; refresh is single-flight; client refuses cross-origin; role-aware rendering; response validation; pages render the server's permissions; attack snippets, scanner text, threat text and AI text render as text; the remove dialog per role; AI decisions need reasons where required |
| Smoke | 69 checks | The running Docker stack through nginx | The whole user journey, end to end, including live detection, the simulated WAF, vulnerability management, governance and the AI engine |
| Scanner rules | `make scan-test` | Annotated examples | Every SentinelEdge Semgrep rule matches what it must and nothing it must not |
| Hardening | 18 checks | Running containers and networks | Non-root, read-only, no capabilities, isolated database, localhost binding, headers, cross-origin isolation |

Backend coverage is 98.0%, against a CI floor of 90%. Database tests deliberately do **not** use SQLite or mocks. The grants, triggers, advisory locks and upsert semantics being tested exist only in PostgreSQL, and the test database is bootstrapped by the same role script used everywhere else.

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
- **Silent scanners.** The gate exits 2 when any expected report is missing or unreadable, so a crashed scanner cannot pass the build.
- **Fixed without a fix.** A scan that did not run the producing scanner cannot mark a finding fixed; a returning finding reopens with a new SLA clock.
- **Risk acceptance abuse.** Non-leads cannot accept; expiries beyond the severity limit are refused; the app role cannot rewrite an acceptance; an expired one reopens its finding.
- **Hostile scanner output.** Over-long strings are bounded and control characters replaced on import.
- **DAST blast radius.** The scanner session is a viewer whose writes are refused, and it stops working once revoked.
- **Self-approval.** Approving your own exception or change is refused by the service, and a direct database update is refused by a CHECK.
- **Rewritten decisions.** Triggers refuse changing a decided exception or reviving a cancelled change, even for a direct update.
- **Catalogue drift.** A document edited without regenerating, or citing a test that does not exist, fails the build.
- **Maintained as code.** Every write to SentinelEdge's own threat model is refused with 409.
- **Prompt injection.** An injection corpus scores high; data cannot close its nonce-delimited block; invisible characters are removed and flagged; injected text cannot change the offline verdict.
- **A compromised model.** A provider that obeys every instruction cannot store invented evidence, propose loosening a WAF rule, add fields of its own or answer with markup: each answer is rejected, never repaired.
- **AI cost.** Limits are checked before the call; a viewer (the DAST scanner) cannot run an analysis.

## Tests that test the tests

Several tests exist to stop the evidence going stale:

- The authorization matrix was mutated on purpose (one route weakened), and three tests failed. This proves the sweep has teeth.
- The OWASP coverage endpoint cites test names, and a test fails if any cited test no longer exists. The control catalogue does the same for every piece of evidence it cites.
- The API inventory's access descriptions are compared with the independently written authorization matrix.
- The capability register's guard tests stop a SIMULATED or future-phase capability being marked as a real, implemented AWS control.
- Every inspection exclusion must name a real route and a real request field, and every correlation rule ID must be unique and documented.

## Continuous integration

GitHub Actions runs on every push and pull request. Besides the security scans (Chapter 10) and the Semgrep rule tests, three jobs run: secret scanning (Gitleaks over full history); the backend (Ruff, mypy strict, Bandit, pip-audit, the role bootstrap, tests with the coverage gate, and an `alembic check` schema-drift gate); and the frontend (`npm ci --ignore-scripts`, ESLint, TypeScript, Vitest, production build, `npm audit`). The token is read-only, and every action is pinned by SHA.
