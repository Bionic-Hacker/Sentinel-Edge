"""The AI security engine (Phase 9; ADR-0006, ADR-0007, ADR-0024).

* `guardrails`: what the model is allowed to see and how: minimised, pseudonymised, bounded
  fields, scored for prompt-injection signals, and delimited as data under a per-call nonce.
* `contract`: what the model must return: one JSON object matching a strict schema, every piece
  of "observed evidence" a verbatim quote of the input, actions only from a fixed list.
  Output that breaks the contract is rejected, never repaired.
* `providers`: who answers: the deterministic `offline` analyser (tests, demos, no cost) or
  Amazon Bedrock. The rest of the engine cannot tell them apart.
"""
