# ADR-0007: AI output contract and human approval

- **Status:** Accepted (implementation in Phase 9)
- **Date:** 2026-10-06
- **Phase:** 9

## Context
AI analysis consumes attacker-controlled content (request bodies, headers, log lines). That
content can carry indirect prompt injection aimed at changing the analysis or triggering
actions (OWASP LLM01, LLM05, LLM06).

## Decision
- **Untrusted-data delimiting:** event data is passed as clearly delimited data, never
  concatenated into instructions, after input validation and prompt-risk scoring.
- **Structured output:** the model must return JSON matching a Pydantic schema with separate
  `observed_evidence` (verbatim facts from the event) and `inference` (the model's
  interpretation), plus classification, severity, and confidence. Non-conforming output is
  rejected, not repaired.
- **Output handling:** AI text is rendered as text, never as HTML or Markdown-to-HTML, and is
  never executed or used to build queries.
- **No agency:** the AI has **no tools that change state**. It can only create an
  `ai_action_proposal`. High-impact actions require an authorised human (SECURITY_ENGINEER or
  ADMIN) to approve, and the approval is audit-logged.

## Security impact
Contains prompt injection to, at worst, a wrong *recommendation* that a human reviews.
Controls C-AI-01..06.

## Consequences
Some AI responses will be rejected for schema violations; the UI shows this rather than
silently degrading.
