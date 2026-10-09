# ADR-0024: The AI security engine as built: guardrails, a verbatim-evidence contract, tighten-only proposals

- **Status:** Accepted
- **Date:** 2026-10-09
- **Phase:** 9
- **Builds on:** ADR-0005 (audit log), ADR-0006 (Amazon Bedrock), ADR-0007 (output contract and
  approval), ADR-0009 (provenance), ADR-0019 (simulated WAF), ADR-0022 and ADR-0023 (governance)

## Context
ADR-0006 chose Amazon Bedrock and ADR-0007 set the rules: untrusted data delimited, structured
output with evidence apart from inference, text-only rendering, no agency. Building it raised
questions those ADRs left open:
- What exactly may reach a model?
- How can a stored answer prove that its "evidence" was really in the data?
- What may the AI propose?
- What does a proposal do once approved?
- How is cost bounded on a portfolio budget of zero?

The data being analysed is attacker-written by design: request paths, user agents, payload
snippets and scanner text. The engine therefore has to be safe even if the model obeys an
injected instruction completely. The tests assume that worst case, and use deliberately hostile
"models".

## Decision

**What the model sees.**
- Analysts choose a **record**, not words. There is no prompt box. The subject can be a security
  event, an incident, a finding or a threat model.
- The service sends only an allow-list of that record's fields, each bounded (500 characters, 12,000
  in all).
- Control characters become spaces, and invisible and bidirectional formatting characters are
  removed. The removal is recorded.
- Addresses and e-mails are pseudonymised (`client-1`, `user-1`).
- The fields travel as JSON between markers that carry a random per-call nonce, so the data cannot
  close its own block. The instructions, outside the block, say that nothing inside it is an
  instruction.
- The input is scored 0 to 100 from named prompt-injection signals (instruction overrides, role
  markers, delimiter spoofing, output steering, forged answers, action names, encoded payloads,
  exfiltration). The score is a **signal for the reviewer**, shown with the answer. It is not a
  gate: attack data is what the engine exists to read.

**What the model must return** (`app/ai/contract.py`).
- One JSON object, parsed strictly: no unknown or duplicate keys, no type coercion, no NaN. A
  single surrounding Markdown fence is tolerated because models add one by habit.
- Every `observed_evidence` item names a field that was sent and quotes it **verbatim**. The
  quote is checked as a substring. An invented "fact" therefore cannot be stored as evidence;
  interpretation goes in `inference`, which the UI labels as not verified.
- Control IDs must exist in the catalogue.
- Proposed actions must be allowed for this subject, at most one of each type.
- Anything else is **rejected, not repaired**. The analysis is stored as rejected, with our own
  reason, and nothing from it is used. A provider error is stored as failed.

**What the AI may propose.** Three actions, all of which tighten:
- **Open an incident:** from an event that no incident tracks yet.
- **Raise a change request:** to set the event's simulated WAF rule back to **block** when it is
  in count mode. "Count" is not in the schema.
- **Add a threat:** to an application's threat model, citing real controls.

Nothing can close, downgrade, delete or loosen anything. A lead (ADMIN or SECURITY_ENGINEER)
approves or rejects each proposal.
- **Approval runs the action as that person** through its own service (incidents, change
  requests, threat models), in the same transaction as the decision. Either both happen or
  neither does.
- **Every action is re-checked at approval:** the event may have been linked to an incident
  since, the rule switched to block, or the model archived.
- **A change request still needs a second lead** (ADR-0023), so even an approved AI suggestion
  passes through separation of duties before anything changes.
- **A high-risk input needs a reason:** approving a proposal from an input scoring 60 or more
  requires a written reason.
- **Decisions are final:** decided proposals cannot change (trigger), and analyses are insert-only.

**Who may run what.**
- ADMIN, SECURITY_ENGINEER and ANALYST analyse anything they can see.
- DEVELOPERs analyse only findings and threat models of their own applications.
- **VIEWERs cannot run analyses.** The authenticated DAST scanner signs in as a viewer (T-VM-06),
  so a scan can never spend tokens or create proposals.
- Analyses and proposals are visible under the same rules as their subjects.

**Cost.** The limits are checked **before** the call, under a per-user advisory lock:
- 20 analyses per user per day;
- 200,000 tokens per day for the platform;
- 800 output tokens per answer.

Each limit is a setting, and over a limit the response is 429. Every call is audited with model,
usage, prompt-risk score, outcome and the SHA-256 of the exact prompt. The provider call happens
before any database write, so no lock is held while a model is thinking.

**Providers.**
- `disabled` is the default.
- `offline` is a deterministic analyser: free, and refused in production. It answers from the
  platform's own verdict, never from the text, and goes through the same parsing and checks.
- `bedrock` uses the Converse API with temperature 0, the token limit and timeouts. An answer
  cut off at the limit is a failure. AWS error messages, which can name accounts and roles, go to
  the log, never to users or the database. See ADR-0006's addendum for the model and credentials.

## Alternatives considered
- **Repairing near-miss answers** (filling missing fields, dropping bad evidence). Rejected: a
  repaired answer is one nobody gave. The UI shows the rejection instead.
- **Blocking high-risk inputs.** Rejected: injection attempts are exactly the events analysts
  most need explained. The defences that matter do not depend on spotting the attempt.
- **Letting the AI call tools.** Rejected (ADR-0007). Proposals reuse the existing workflows,
  which already have role rules, separation of duties and audit.
- **A free-text "ask the AI" box.** Deferred. It would make direct injection (T-AI-01) a feature,
  and the record-based design covers the specification's analysis use cases.

## Incidents during the phase (kept as lessons)
1. **A formatter changed a security regex.** `ruff format` rewrote escaped invisible-character
   ranges as the literal characters, which made the source unreadable and fragile. Bandit (B613,
   trojan-source characters) flagged it. The pattern is now written with escapes, and a test
   checks that invisible characters are removed.
2. **The audit log redacted the token counts.** The log's redaction treats keys that look like
   credentials (`token`) as secrets, so `tokens` was stored as `[REDACTED]`. The usage is now
   recorded as `usage: {input, output}`. The redaction was right; the key name was wrong.
3. **The edge would have cut real answers off.** nginx allows the API 30 seconds; a Bedrock call
   may take longer, with one retry. Only `POST /api/v1/ai/analyses` gets 75 seconds, and the SPA
   waits 80. This was found in review before any real call timed out.

## Consequences
- The engine can be demonstrated and tested end to end at no cost (`offline`). `make ai-check`
  checks a real model against the same contract for about a thousand tokens.
- Six endpoints (85 in all), two tables (migration 0014), an AI Security page, and "Analyze with
  AI" on events, incidents, findings and threat models.
- Threats T-AI-01 to T-AI-06 mitigated, and T-AI-07 to T-AI-10 added. Controls C-AI-01 to C-AI-07
  are implemented.
