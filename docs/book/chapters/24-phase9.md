# Phase 9 — AI Security Engine

<p class="lead">AI in SentinelEdge is a security-intelligence component, not a chatbot. It analyzes events and findings, explains risk and recommends controls, and it is never allowed to act on its own. <span class="status plan">Planned</span></p>

## Scope

The engine analyzes WAF events, API events, HTTP requests, security logs, vulnerability findings, threat-model findings and incident data. It produces summaries, risk explanations, attack classifications, remediation recommendations and threat-model suggestions, using Amazon Bedrock through the IAM task role (ADR-0006).

## The output contract (ADR-0007)

Attacker-controlled content (request bodies, headers, log lines) flows into the analysis, so indirect prompt injection is the primary threat (OWASP LLM01). The defenses:

- **Untrusted data is delimited, never concatenated into instructions**, after input validation and prompt-risk scoring.
- **Structured output.** The model must return JSON matching a Pydantic schema. `observed_evidence` (verbatim facts from the event) is kept separate from `inference` (the model's interpretation), alongside classification, severity and confidence. Non-conforming output is **rejected, not repaired**, and the UI says so.
- **Output handling.** AI text is rendered as text only, never as HTML or Markdown-to-HTML, and never executed or used to build queries.
- **No agency.** The AI has no tools that change state. It can only create an `ai_action_proposal`. High-impact actions need SECURITY_ENGINEER or ADMIN approval, which is audited.
- **Data minimization and cost.** Only redacted, minimized event data is sent, with no credentials, tokens or PII fields. Every invocation is audit-logged with model, token counts and prompt-risk score, and bounded by per-user quotas (LLM10).
- **Safe egress.** Outbound calls pass the Phase 6 SSRF guard.

:::planned Test plan
A prompt-injection corpus (direct, indirect via log lines, encoded and multi-step) must fail to change classifications or produce proposals outside the schema. The `offline` provider makes these tests deterministic and free. Bedrock is the one AWS service used before the AWS window: on-demand calls, pennies, no infrastructure.
:::
