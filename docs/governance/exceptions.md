# Security exceptions register

Spec §38 requires every exception to name a requester, business justification, risk,
compensating control, approver, and expiry. This register is the system of record until the
governance module (Phase 10) stores exceptions in the application; at that point these entries
are migrated, not retyped.

**Rules**

- An exception never removes a control silently. Each one names what still protects the system.
- Every exception expires. On expiry it is either closed (the underlying issue is fixed) or
  renewed with a fresh review — never left to lapse.
- Configuration that implements an exception (for example a Dependabot `ignore` rule) carries
  the exception ID in a comment, so the link can be audited in both directions.

## Open exceptions

### EXC-0001 — ESLint held on major version 9

| Field | Value |
|---|---|
| Status | Open |
| Requester | Bionic-Hacker (project owner) |
| Raised | 2026-10-07 |
| Affected component | `frontend` dev tooling: `eslint`, `@eslint/js` |
| Trigger | Dependabot PR #1 proposed ESLint 10. CI failed at `npm ci`: `eslint-plugin-jsx-a11y@6.10.2`, the latest release, declares a peer range of ESLint ≤9. |
| Business justification | The accessibility rule set is a required quality control for the UI. Upgrading ESLint would mean removing it or forcing an unsupported install (`--legacy-peer-deps`), which defeats lockfile integrity. |
| Risk | Low. ESLint 9 no longer receives upstream support. ESLint is a development-time tool that is never shipped to users; the residual risk is missing future lint-rule improvements and fixes in the linter itself. |
| Compensating controls | `npm audit` gates every CI run and reports no known vulnerabilities in the ESLint 9 tree; all security lint rules (bans on `dangerouslySetInnerHTML`, `innerHTML`, `eval`, web storage) still run on every commit; Dependabot still proposes ESLint 9.x minor and patch updates. |
| Implementation | `.github/dependabot.yml` ignores semver-major updates of `eslint` and `@eslint/js` (comment `EXC-0001`). |
| Exit criteria | `eslint-plugin-jsx-a11y` publishes a release supporting ESLint 10, then upgrade and close. |
| Approver | Bionic-Hacker |
| Expires | 2027-01-07 (90 days) — review earlier when the plugin releases |

### EXC-0002 — TypeScript held below major version 7

| Field | Value |
|---|---|
| Status | Open |
| Requester | Bionic-Hacker (project owner) |
| Raised | 2026-10-07 |
| Affected component | `frontend` dev tooling: `typescript` |
| Trigger | Dependabot's npm update job failed resolving TypeScript 7.0.2: `typescript-eslint@8.71.1` supports `typescript >=4.8.4 <6.1.0`. |
| Business justification | Type-aware lint rules from `typescript-eslint` are part of the frontend quality gate. |
| Risk | Low. TypeScript is a build-time tool; its output is plain JavaScript, scanned by `npm audit` like any other dependency. |
| Compensating controls | `tsc` strict mode and all lint rules continue to gate every commit; minor and patch updates still flow. |
| Implementation | `.github/dependabot.yml` ignores semver-major updates of `typescript` (comment `EXC-0002`). |
| Exit criteria | `typescript-eslint` supports TypeScript 7, then upgrade and close. |
| Approver | Bionic-Hacker |
| Expires | 2027-01-07 (90 days) |

## Closed exceptions

None yet.
