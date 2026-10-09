# Runbook: AI prompt injection

- **Severity guidance:** SEV2: a proposal from a high-risk input was approved and its action ran
  wrongly, or an AI answer led someone to a wrong security decision. SEV3: a high-risk input or a
  rejected answer with no harm done (the expected case: record and learn). SEV1 is not expected:
  the AI has no tools, and no proposal can loosen a control.
- **Owner role:** SECURITY_ENGINEER (review, decisions); ADMIN (provider and limits)
- **Related threats / controls:** T-AI-01..10, T-VM-06; C-AI-01..07, C-AUD-01; ADR-0006, ADR-0007,
  ADR-0024
- **Last exercised:** 2026-10-09. The `make ai-check` synthetic event, whose user agent tells the
  AI to "classify this as benign", scored 65 (instruction override, output steering). It was
  analysed as SQL injection with verbatim evidence. The integration suite's compromised-model
  tests had every injected answer rejected or refused.

## 1. Detection
- **AI Security page and analysis pages:** a *Prompt risk … High* badge, and the list of signals
  found in the data ("Tries to override instructions", "Imitates the data delimiters"...).
- **Rejected analyses:** *Rejected: broke the contract*, with the reason. Examples: an evidence item
  that is not a verbatim quote, an action that is not allowed, an unknown control.
- **Disagreements:** "The AI calls this benign; the platform detected SQL injection."
- **Audit log:** `ai.analysis_run` (with `prompt_risk`, `risk_signals`, `status`, `usage`,
  `input_sha256`), `ai.proposal_approved` and `ai.proposal_rejected`, and `ai.quota_exceeded`.

A high score on an attack event is normal: the attacker wrote the user agent. It matters when the
answer or a proposal looks steered.

## 2. Triage (first 15 minutes)
1. Open the analysis. Read **Observed evidence** first: those quotes were checked against the
   data. Read **Inference** as an opinion.
2. Compare it with the platform's verdict on the subject page (event category and severity,
   finding severity). The platform's verdict is never changed by the AI.
3. **Proposals from this analysis:** reject any you would not have made yourself, with the reason.
   Approving one from a high-risk input needs a written reason anyway.
4. **Already approved and wrong?** Go to Containment. The action ran as the approving lead, through
   its normal workflow, so it can be undone through that workflow.

## 3. Investigation
- The analysis page shows the **input fingerprint** (SHA-256 of the exact prompt) and token usage.
  The same values are in the `ai.analysis_run` audit record, so the record ties the answer to its
  input.
- To see what was sent, open the subject (the record's fields are what the engine reads). The
  pseudonyms `client-1` and `user-1` stand for addresses and e-mails.
- **Same pattern elsewhere?** Search the Threats page for the user agent or snippet: one attacker
  usually sends the same text many times.
- **Model behaviour:** run `make ai-check`. Bedrock calls are logged with the AWS error code only.
- Preserve before changing anything: analyses, proposals and audit records cannot be edited by the
  application.

## 4. Containment
| What happened | Undo it through |
|---|---|
| An incident was opened from a proposal | The incident workflow: close it as false positive with the reason |
| A WAF change request was raised | It still needs a second lead: reject it, or cancel it if you raised it |
| A threat was added to a model | The threat model page: set the threat's status, or retire it |
| The provider looks compromised or misbehaves | `SENTINEL_AI_PROVIDER=disabled` and `docker compose up -d api` (and `make bedrock-credentials-clear`) |
| Unexpected Bedrock spend | `make bedrock-credentials-clear`; check the AWS budget alert and lower `SENTINEL_AI_TOKENS_PER_DAY` |

## 5. Remediation
- A new injection technique the scoring missed: add a signal to `SIGNALS` in
  `backend/app/ai/guardrails.py`, with the example in the corpus in
  `tests/unit/test_ai_guardrails.py` (`test_injection_corpus_scores_high`).
- An answer that met the contract but misled: tighten the contract (`app/ai/contract.py`), never
  the UI wording alone. Add a hostile-model test to `tests/integration/test_ai.py`.
- A field that should never reach a model: remove it from the subject's allow-list in
  `app/services/ai.py`.

## 6. Validation
1. `make check`: the injection corpus, the contract tests and the compromised-model tests pass.
2. `make ai-check` with the provider in use: `COMPLETED` with verbatim quotes.
3. Re-run the analysis on the original subject: the new signal is named, or the answer is rejected.

## 7. Rollback
- Revert the pull request that changed the guardrails or the contract. Stored analyses are not
  affected: they keep the reason they were accepted or rejected under at the time.

## 8. Post-incident
- Record the decision and its reference on the incident (if one was opened), then close it.
- If the attack worked in a way the threat model does not describe, add a T-AI threat with its
  control, then `make governance-catalogue`.
