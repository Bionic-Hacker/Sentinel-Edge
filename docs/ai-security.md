# AI security engine

The engine explains security data and may propose an action; a human decides. This page is the
reference: what it does, how to switch it on, who may use it, and where each safeguard lives. The
reasons are in [ADR-0006](adr/0006-amazon-bedrock-ai-provider.md),
[ADR-0007](adr/0007-ai-output-contract-and-approval.md) and
[ADR-0024](adr/0024-ai-security-engine.md).

## What it analyses

| Subject | Fields sent (allow-list, each at most 500 characters) | Possible proposal |
|---|---|---|
| Security event | Title, source, category, severity, outcome, method, endpoint, status, rule, user agent, redacted evidence; client address and account pseudonymised | Open an incident (if none tracks the event); set its simulated WAF rule back to block (if it is in count mode) |
| Incident | Title, summary, severity, category, status, detection rule, remediation, linked events (up to 10); client pseudonymised | None |
| Finding | Title, tool, category, rule, severity, component, location, CVE, CVSS, fixed version, recommendation, status | None |
| Threat model | Name, method, application, scope, assets, boundaries, flows, existing threats and the STRIDE letters they cover | Add a threat for a missing STRIDE category, citing real controls (application models only) |

## Providers

| `SENTINEL_AI_PROVIDER` | What answers | Cost | Provenance shown |
|---|---|---|---|
| `disabled` (default) | Nothing: analyses are refused (503 `ai_disabled`) | None | — |
| `offline` | A deterministic analyser that answers from the platform's verdict, never from the text | None | LOCAL |
| `bedrock` | Amazon Bedrock, Nova Micro by default ([setup](bedrock-setup.md)) | A fraction of a cent per analysis | REAL_AWS (calls only; no infrastructure) |

`offline` is refused in production by configuration validation.

## Limits

| Setting | Default | Checked |
|---|---|---|
| `SENTINEL_AI_REQUESTS_PER_USER_PER_DAY` | 20 | Before the call (429 `ai_quota_exceeded`) |
| `SENTINEL_AI_TOKENS_PER_DAY` | 200,000 (all users) | Before the call |
| `SENTINEL_AI_MAX_OUTPUT_TOKENS` | 800 | Sent as the model's limit; a cut-off answer is a failure |
| `SENTINEL_AI_TIMEOUT_SECONDS` | 30 | Bedrock read timeout, one retry; nginx allows the endpoint 75 s |

## Who may do what

| Action | ADMIN, SECURITY_ENGINEER | ANALYST | DEVELOPER | VIEWER |
|---|---|---|---|---|
| See the engine's status | ✓ | ✓ | ✓ | ✓ |
| Run an analysis | ✓ | ✓ | Own applications' findings and threat models | |
| Read analyses and proposals | ✓ | ✓ | Own applications' | ✓ |
| Approve or reject a proposal | ✓ | | | |

Viewers never run analyses: the authenticated DAST scanner is a viewer.

## Safeguards and where they live

| Safeguard | Code | Control |
|---|---|---|
| Allow-listed, bounded, pseudonymised fields; invisible characters removed | `backend/app/ai/guardrails.py` | C-AI-01, C-AI-04 |
| Prompt-risk score with named signals, shown with the answer | `guardrails.SIGNALS` | C-AI-01 |
| Data delimited under a per-call nonce | `guardrails.build_prompt` | C-AI-01 |
| The catalogue's control IDs and titles given to the model as trusted context, outside the data block | `guardrails.control_menu` | C-AI-02 |
| Strict JSON; verbatim evidence; known controls; allowed, tighten-only actions | `backend/app/ai/contract.py` | C-AI-02, C-AI-05 |
| Text-only rendering; responses validated in the SPA | `frontend/src/features/ai/`, `lib/api/aiValidators.ts` | C-AI-03 |
| Lead approval, as that person, in one transaction; decisions final | `backend/app/services/ai.py`, migration 0014 | C-AI-05 |
| Limits before the call; every call audited | `AiService._check_quota`, audit `ai.analysis_run` | C-AI-06 |
| One IAM permission; session credentials; AWS errors kept out | `backend/app/ai/bedrock.py`, `scripts/bedrock-credentials.sh` | C-AI-07 |

## Endpoints

| Endpoint | Purpose |
|---|---|
| `GET /api/v1/ai/status` | Provider, model, provenance, the caller's usage and the limits |
| `POST /api/v1/ai/analyses` | Analyse one subject (`{subject_type, subject_id}`) |
| `GET /api/v1/ai/analyses`, `/ai/analyses/{id}` | Analyses, filterable by subject; one with its output and proposals |
| `GET /api/v1/ai/proposals` | Proposals with counts, filterable by status |
| `POST /api/v1/ai/proposals/{id}/decision` | Approve or reject (`{version, decision, note}`) |

Incidents: [AI prompt injection runbook](runbooks/ai-prompt-injection.md).
