# ADR-0006: Amazon Bedrock as the AI provider

- **Status:** Accepted (integration in Phase 9; no AI code in Phase 1)
- **Date:** 2026-10-06
- **Phase:** 9

## Context
The AI security engine analyses WAF events, logs, and findings. Provider choice affects
credential handling, data residency, network exposure, and how the design reads in an AWS
security interview.

## Decision
Use **Amazon Bedrock** (Anthropic Claude models) behind a provider interface.

Architectural accounting made now:
- **Authentication:** the ECS application task role is granted `bedrock:InvokeModel` on the
  specific model ARNs only. No API key exists, so there is no AI secret to store or leak.
- **Network:** calls go to the Bedrock runtime endpoint. Phase 4 decides between NAT egress and
  a `com.amazonaws.<region>.bedrock-runtime` interface VPC endpoint (about $7/month per AZ);
  the endpoint keeps prompts off the public internet and allows an endpoint policy.
- **Data handling:** only redacted, minimised event data is sent; no credentials, tokens, or
  synthetic PII fields. Bedrock does not use inputs to train models.
- **Configuration:** `SENTINEL_AI_PROVIDER` is already validated (`disabled | offline | bedrock`);
  default is `disabled`. The `offline` provider is a deterministic local analyser for tests and
  demos and is rejected in production by configuration validation.
- **Audit and cost:** every invocation is audit-logged (model, token counts, prompt-risk score)
  and bounded by per-user quotas.

## Security impact
Removes an entire secret class (API keys), enables IAM least privilege and CloudTrail visibility
of model invocations, and supports private connectivity. Addresses T-AI-04 (sensitive data
disclosure) and T-AI-05 (excessive agency, together with ADR-0007).

## Alternatives considered
Anthropic API directly — equally capable models, but needs an API key in Secrets Manager and
public egress. Kept as a drop-in alternative behind the provider interface.

## Consequences
Bedrock model access must be enabled per account and region. Local development uses the
`offline` provider, so tests never call a paid model.
