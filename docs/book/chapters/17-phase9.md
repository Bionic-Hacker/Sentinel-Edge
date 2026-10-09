# Phase 9 — AI Security Engine

<p class="lead">AI in SentinelEdge is a security-intelligence component, not a chatbot. It explains security events, incidents, findings and threat models, classifies them, recommends controls, and may propose an action that a human approves. It reads attacker-written data by design, so it is built to stay safe even if the model obeys every instruction hidden in that data. Released as v0.7.0.</p>

## Milestones

| Milestone | Delivered |
|---|---|
| M1 | The engine, offline: guardrails, the output contract, proposals with lead approval, limits, migration 0014, six endpoints, an injection corpus and deliberately compromised test "models" |
| M2 | The Amazon Bedrock provider (Nova Micro by default), short-lived local credentials, `make ai-check`, a one-permission IAM policy |
| M3 | The AI Security page, the analysis page, "Analyze with AI" on four kinds of record, proposal decisions, five smoke checks |
| M4 | ADR-0024 and the ADR-0006 addendum, threat model v0.7, the prompt-injection runbook, Edition 5 of this book, v0.7.0 |

## The design question

A security event's user agent is written by the attacker. So is a request path, a payload snippet, and often the text of a finding. An engine that explains these to an analyst therefore reads text written to manipulate it (OWASP LLM01, indirect prompt injection). Filtering that text out is not an option, because it is the evidence.

The engine therefore assumes the model may be fully compromised. The tests use a "model" that obeys every instruction it is given, and the question each defence answers is: *what is the worst such a model can do?* The answer, by construction, is a rejected answer or a proposal that a human reviews and that can only tighten a control.

{{figure:ai|The analysis pipeline. Limits are checked before anything is sent. The provider sits between two fixed stages: what it may see, and what its answer must prove.|60}}

## What the model sees

There is **no prompt box**. An analyst chooses a record, and the service sends only an allow-list of its fields (title, category, severity, outcome, endpoint, rule, user agent and redacted evidence for an event). Each field is bounded to 500 characters, 12,000 in all.

- Control characters become spaces. **Invisible and bidirectional characters are removed**, and the removal is recorded. Such characters render as nothing to a reviewer but are read by a model.
- Addresses and e-mails are **pseudonymised** (`client-1`, `user-1`). The model needs the pattern, not the person.
- The fields travel as JSON between markers that carry a **random per-call nonce**. The data cannot close its own block, because it cannot know the marker. The instructions sit outside the block and say that nothing inside it is an instruction.

The input is also **scored** from 0 to 100 for prompt-injection signals:

- instruction overrides;
- role markers;
- imitations of the delimiters;
- attempts to dictate the answer;
- forged answers;
- action names;
- encoded payloads;
- exfiltration requests.

:::why Why a high score does not block
Injection attempts are exactly the events an analyst most needs explained, so blocking them would hide the attacks the engine exists for. The score is a signal for the reviewer: it is shown with the answer, and approving anything from an input scoring 60 or more requires a written reason. The defences that matter work whether or not the attempt was spotted.
:::

## What the model must return

The answer must be **one JSON object**, parsed strictly: no unknown or duplicate keys, no type coercion, no NaN. A single Markdown fence is tolerated, because models add one by habit. The fields are a summary, a classification, a severity, a confidence, `observed_evidence`, `inference`, recommendations and proposed actions.

- **Evidence must be verbatim.** Each `observed_evidence` item names a field that was sent and quotes it. The quote is checked as a substring of that field. A model cannot store an invention as a fact, however confidently it writes it.
- **Interpretation is labelled.** `inference` is where conclusions go, and the page labels it *the model's interpretation: not a fact, not verified*.
- **Controls must exist** in the catalogue (Chapter 11).
- **Actions must be allowed** for this subject, at most one of each type.

Anything else is **rejected, not repaired**. The analysis is stored as rejected with our own reason, and the page shows it with nothing from the answer. A provider error is stored as failed.

:::lesson A repaired answer is one nobody gave
It is tempting to drop the one bad evidence item and keep the rest. But then the stored answer would not be what the model said, and its good-looking parts would carry an authority they did not earn. Rejection is visible and honest; the analyst can run the analysis again.
:::

## The AI cannot act

The AI has no tools. It can propose three actions, all of which **tighten** a control:

| Proposal | When it is allowed |
|---|---|
| Open an incident with the event as evidence | The event is not yet part of an incident |
| Raise a change request to set the event's simulated WAF rule back to **block** | The rule is in count mode; "count" is not in the schema |
| Add a threat to an application's threat model, citing real controls | The model is an application model with a STRIDE category uncovered |

A lead (admin or security engineer) approves or rejects each proposal; rejection needs a reason.

- **Approval runs the action as the lead.** It goes through the action's own service (incidents, change requests, threat models), in the same transaction as the decision, so either both happen or neither does.
- **Every action is re-checked at approval time.** The event may have been linked since, the rule switched back, or the model archived.
- **A change request still needs a second lead** (Chapter 11), so even an approved suggestion passes separation of duties before anything changes.
- **Decisions are final.** A trigger refuses any change to a decided proposal, and analyses are insert-only for the application.

:::evidence A compromised model, end to end
The integration tests replace the provider with one that does whatever the injected text says:

- **Fabricated evidence:** it claims evidence that is not in the data, and the answer is rejected.
- **Weakening a rule:** it proposes switching the WAF rule to count, and the answer is rejected.
- **Instructions of its own:** it adds a field the schema does not have (`delete_audit_log`), or answers with a `<script>` tag instead of JSON, and the answer is rejected.
- **A "benign" verdict:** it calls an SQL injection benign. The answer is stored with a visible disagreement ("the platform detected SQL injection"), and the platform's verdict is unchanged.
:::

## Who may use it, and what it costs

| Action | Admin, security engineer | Analyst | Developer | Viewer |
|---|---|---|---|---|
| Run an analysis | ✓ | ✓ | Own applications' findings and threat models | |
| Read analyses and proposals | ✓ | ✓ | Own applications' | ✓ |
| Approve or reject a proposal | ✓ | | | |

**Viewers cannot run analyses.** The authenticated DAST scanner signs in as a viewer (Chapter 10), so a scan can never spend tokens or create proposals.

The limits are checked **before** the call, under a per-user lock:

- 20 analyses per user per day;
- 200,000 tokens per day for the platform;
- 800 tokens per answer.

Over a limit, the response is 429 and the refusal is audited. Every call is audited with its model, usage, prompt-risk score, outcome and the SHA-256 of the exact prompt, so a disputed answer can be tied to its input. The provider is called before anything is written, so no database lock is held while a model is thinking.

## Providers

| Provider | What answers | Cost |
|---|---|---|
| `disabled` (default) | Nothing: the engine refuses with 503 | None |
| `offline` | A deterministic analyser that answers from the platform's own verdict, never from the text; refused in production | None |
| `bedrock` | Amazon Bedrock through the Converse API: Nova Micro by default, temperature 0, bounded tokens and time | A fraction of a cent per analysis |

The offline analyser's answers go through exactly the same parsing and checks as a real model's. The whole engine can therefore be built, tested and demonstrated for nothing, and the AI category of the posture score (Chapter 11) measured.

**Bedrock without infrastructure.** Nova Micro is an Amazon model, so new-account credits apply and no Marketplace subscription is involved.

- **Credentials:** the IAM user behind the local credentials holds one permission, `bedrock:InvokeModel`, on that one model. `make bedrock-credentials` exchanges its keys for a session of up to twelve hours. The session is written to a git-ignored, mode-600 file that the API container loads only if it exists, so long-lived keys never enter a container.
- **Error text:** AWS error messages can name accounts and roles, so they go to the log, never to users or the database.
- **Answer length:** an answer cut off at the token limit is a failure, not a partial answer.

`make ai-check` sends one synthetic event, with an injection attempt in its user agent, through the configured provider and the contract. It costs about a thousand tokens.

:::lesson The edge would have cut real answers off
nginx gives the API 30 seconds; a real model can take longer, with one retry. Only `POST /api/v1/ai/analyses` gets 75 seconds, and the page waits 80. The limit was found in review, before any real call timed out. A timeout is part of the interface, not an implementation detail.
:::

:::lesson Redaction worked; the key name was wrong
The audit log redacts values under keys that look like credentials, so `tokens` was stored as `[REDACTED]`. The usage is now recorded as `usage: {input, output}`. Changing the redaction would have been the wrong fix.
:::

## The frontend

**AI Security** shows:

- the provider, model and provenance;
- your usage against the daily limits;
- proposals awaiting a decision;
- recent analyses with their prompt-risk level.

An **analysis page** shows:

- the signals found in the input;
- the observed evidence (each quote with its field, attacker text rendered as text) beside the inference;
- any disagreement with the platform;
- recommendations with their control IDs;
- the proposals, each with what approving would do, in plain words.

**Analyze with AI** appears on security events, incidents, findings and threat models, with links to earlier analyses, only when the engine is on and the server says the user may run one. The SPA validates every AI response, including refusing an action the contract does not allow.

## Verified

:::evidence Phase 9 at release
- **Tests:** 991 backend tests (98.0% coverage) against real PostgreSQL and 115 frontend tests. They include an injection corpus, hostile and malformed answers, the compromised-model tests, and Bedrock calls answered by botocore's stubber.
- **Smoke:** `make smoke` runs 69 checks. A viewer can neither run an analysis nor decide a proposal, and malformed requests are refused before any call. With `offline`, the injection event is analysed and its proposals rejected; with AI off, analyses are refused. The smoke test never calls Bedrock.
- **Threat model v0.7:** T-AI-01 to T-AI-06 mitigated; T-AI-07 (fabricated evidence) to T-AI-10 added. Controls C-AI-01 to C-AI-07 implemented.
- **Browser:** the AI pages checked in headless Chromium at 1440 and 390 px wide.
:::
