# ADR-0006: Amazon Bedrock as the AI provider

- **Status:** Accepted; implemented in Phase 9 (see the addendum and ADR-0024)
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

## Addendum (Phase 9, 2026-10-09): model and local credentials

- **Default model: Amazon Nova Micro** (`amazon.nova-micro-v1:0`), set by `SENTINEL_AI_MODEL`.
  It is an Amazon model, so new-account AWS credits apply and no AWS Marketplace subscription
  is involved. It is also the cheapest model that meets the output contract. Anthropic Claude models remain
  supported through the same Converse API (the decision above), but are billed through AWS
  Marketplace. The model ID is validated by pattern, so it cannot be a URL or a path.
- **Local credentials:** `make bedrock-credentials` exchanges an AWS CLI profile for a session of
  1 to 12 hours, written to `.env.bedrock` (git-ignored, mode 600) and loaded by the API container
  only if present. Long-lived keys never enter a container. The IAM user behind the profile holds
  one permission: `bedrock:InvokeModel` on that one model ([setup](../bedrock-setup.md)).
- **Network:** locally, the API reaches Bedrock over the internet from the `edge` network; the
  database network stays internal. The Phase 4 choice between NAT and a VPC endpoint stands.
- **Not built:** no infrastructure exists for Bedrock. Calls are on demand, and `disabled` stays
  the default.
