# Security assessment

SentinelEdge's own review of itself at the end of the build (Phase 12, October 2026), as an
assessor would write it: what was examined, what holds, what was fixed, and what risk remains.
Every claim points at evidence in the repository; the threat model is
[docs/threat-model.md](docs/threat-model.md) (v0.14) and the controls
[docs/security-controls.md](docs/security-controls.md).

## Scope and method

The application (FastAPI, React), its database, the AWS workload and edge, the Terraform, the CI
pipeline and the AI engine. Method: the threat model reviewed threat by threat against code and
tests; every control's cited evidence checked to exist (a test does this on every build); the
scanners in the gate run fresh; IAM and Terraform read line by line; two deploy windows treated
as live tests.

## Results by area

| Area | Examined | Result |
|---|---|---|
| Dependencies | pip-audit, npm audit, Trivy (filesystem and images), SBOMs | No known vulnerability in Python dependencies; image findings are Debian packages with no published fix, reported every run and blocking once one ships |
| Authentication | Argon2id, JWT handling, refresh rotation, MFA, lockout, recovery | Holds. **Hardened in Phase 12:** tokens carry a key ID and a previous key verifies during a rotation, so the signing key can be rotated without signing everyone out |
| Authorization | Route table vs the expected matrix, sweep as every role, object rules | Holds: 89 endpoints, each with one declared access class, swept on every build |
| API | Rate limits, inventory, OWASP API Top 10 | API1–5, 7–10 mitigated or not exposed; API6 partial (no Bot Control, see residual risk) |
| IAM | Every policy in Terraform | Least privilege per task; the two `*` resources are actions with no resource-level permission (`ecr:GetAuthorizationToken`, `acm:ListCertificates`); KMS key policies use `*` for "this key", as AWS requires |
| Terraform | Checkov (578 passed, 0 failed), TFLint, 62 module test runs | Every Checkov skip is written beside its resource with a reason |
| Edge and WAF | `make edge-check` (21 checks) in two windows; WAF rules and logging | Holds: private origin unreachable, headers identical to local, SQLi and Log4j blocked; 198 real blocks read back in the first window |
| Containers | Hardening checks, image scans | Non-root, read-only, no capabilities, no shell in AWS; images by digest |
| CI/CD | Workflows, pinning, permissions, credentials | Actions pinned by SHA, read-only token, **no AWS credential exists** (ADR-0030); deploy refuses anything not green |
| AI | Guardrails, output contract, proposals, limits | Holds: delimited and pseudonymised input, verbatim-evidence contract, tighten-only proposals a lead approves, quotas before every call |
| Audit | Hash chain, grants, triggers, anchors | Holds; tail deletion detected through hourly S3 Object Lock anchors (verified in both windows) |

## Fixed during the assessment

- Long Terraform applies failed when `aws login` credentials expired mid-apply: Terraform now
  renews them (second window finding).
- `edge-check` could not verify the private origin on networks that hide private DNS answers,
  and its reachability check passed vacuously on an empty lookup: both fixed.
- Signing-key rotation (above).
- Five runbooks that were still planned: application outage, origin connectivity, TLS failure,
  certificate expiration, WAF false positive. Disaster recovery documented with RTO and RPO.

## Residual risk (accepted)

| Risk | Why accepted | Compensating controls |
|---|---|---|
| A distributed attacker can lock out a known account (T-ID-10) | WAF Bot Control and CAPTCHA cost more than this platform warrants | Per-IP and per-account limits, WAF sign-in rate rule, 15-minute lockout, MFA |
| HS256 with a shared key, not asymmetric keys | One service signs and verifies; asymmetric keys add a key-distribution problem without a second verifier | 256-bit key, pinned algorithm, key IDs and rotation, 15-minute tokens checked against a live session |
| Single-AZ database, one NAT, Spot tasks in dev | Cost; the environment exists only in deploy windows | Synthetic data; RTO and RPO above |
| Rate-limit and metrics writes load the database | Fine at this scale; a cache is a later concern | Statement timeout; limiter fails closed |
| Deployment depends on the owner's machine | The account denies OIDC; a stored key is worse | Deploy gated on green CI; saved plans read by a person |
| No DNSSEC | The registrar cannot hold a DS record for a delegated name | CAA (Amazon only, no wildcards), query logging, `prevent_destroy` on the zone |

## Open item

A passive ZAP baseline of the live edge (`make dast-edge`, C-CICD-12) runs in the Phase 12 deploy
window; its result is added here.
