# Amazon Bedrock for the AI engine (Phase 9)

The AI engine runs without AWS: `SENTINEL_AI_PROVIDER=offline` is a deterministic local
analyser that goes through exactly the same guardrails, contract and approval workflow, at no
cost. This page is for when you want a real model to answer. It is the only part of SentinelEdge
before the AWS window (Phases 3 to 5) that touches AWS, and it creates no infrastructure: on-demand
model calls only ([ADR-0006](adr/0006-amazon-bedrock-ai-provider.md)).

## What it costs

The default model is **Amazon Nova Micro**, called through its US cross-region inference profile
(`us.amazon.nova-micro-v1:0`; in us-east-2 the model is offered only that way), about $0.035 per million
input tokens and $0.14 per million output tokens on demand (check the Bedrock pricing page for
your region). It is an Amazon model, so new-account AWS credits apply to it; Anthropic and other
third-party models are billed through AWS Marketplace, which credits do not cover.

| Bound | Default | Set with |
|---|---|---|
| Tokens per answer | 800 | `SENTINEL_AI_MAX_OUTPUT_TOKENS` |
| Analyses per user per day | 20 | `SENTINEL_AI_REQUESTS_PER_USER_PER_DAY` |
| Tokens per day, all users together | 200,000 | `SENTINEL_AI_TOKENS_PER_DAY` |

One analysis is about 1,000 to 3,000 input tokens and a few hundred output tokens: a fraction of a
cent. At the daily ceiling the platform cannot spend more than a few cents a day. The engine
checks the limits **before** calling the model and refuses with 429 once one is reached.

## One-time setup

SentinelEdge's account (see [aws-setup.md](aws-setup.md)) has no IAM users and no access keys:
you sign in with `aws login`. That session can do anything you can, so it never enters a
container. Instead, the account stack creates **`sentineledge-local-bedrock`**, a role that may
call `bedrock:InvokeModel` on the Nova Micro US inference profile, and on the model itself only
through that profile, and nothing else
(`terraform/account/bedrock.tf`), and `make bedrock-credentials` gives the local API a session of
that role only.

1. **The budget** already exists (the bootstrap stack: $30 a month, alerts at $5, $15 and $30).
2. **The role:** apply the account stack (`make tf-plan STACK=account`, then `make tf-apply
   STACK=account`).
3. **The region and model:** in `.env`, `SENTINEL_AWS_REGION=us-east-2` and
   `SENTINEL_AI_MODEL=us.amazon.nova-micro-v1:0` (older `.env` files say us-east-1 and the bare
   model ID).

Amazon models need no Marketplace subscription. If the Bedrock console still shows a *Model
access* page with Nova Micro not granted, request access there (free, immediate for Amazon models).

**Another account with an IAM user instead.** Give the user only the `InvokeModel` statement from
`terraform/account/bedrock.tf` (with that account's Region in the ARN), store its access key with
`aws configure --profile <name>`, and run `make bedrock-credentials AWS_PROFILE=<name>`: the keys
stay on your machine and are exchanged for a session of up to `HOURS` (1 to 12).

## Each time you want Bedrock

```fish
cd ~/Sentinel-Edge/sentineledge
aws login --profile sentineledge  # if your sign-in has expired (12 hours)
make bedrock-credentials          # writes .env.bedrock: a 1-hour session of the one-model role
```

In `.env`, set:

```
SENTINEL_AI_PROVIDER=bedrock
```

Then reload the API and check the provider end to end:

```fish
docker compose up -d api
make ai-check
```

`make ai-check` sends one synthetic security event (with a prompt-injection attempt in its user
agent) and checks the answer against the output contract. Expected, after a few seconds:

```
Provider bedrock, model us.amazon.nova-micro-v1:0
Prompt risk 65 (instruction_override, output_steering)
Usage 850 input + 300 output tokens
COMPLETED: classification sql_injection, severity high, 2 verbatim quotes, 1 proposed actions
```

The numbers vary. `REJECTED: ...` means the model answered but broke the contract (the answer is
not used); `FAILED: ...` means the call itself failed, with the reason.

## Switching it off

```fish
make bedrock-credentials-clear    # deletes .env.bedrock and reloads the API without AWS credentials
```

and set `SENTINEL_AI_PROVIDER=offline` (or `disabled`) in `.env`, then `docker compose up -d api`.
The role costs nothing while unused; it is removed with the account stack.

## Troubleshooting

| `make ai-check` says | Cause | Fix |
|---|---|---|
| `No AWS credentials` | `.env.bedrock` missing, or the API was not reloaded | `make bedrock-credentials`, then `docker compose up -d api` |
| `The AWS session credentials have expired` | The role session lasts one hour | `make bedrock-credentials` again (after `aws login` if your sign-in expired too) |
| `Could not assume sentineledge-local-bedrock` | The account stack is not applied, or your sign-in expired | `make tf-plan STACK=account` and apply; or `aws login --profile sentineledge` |
| `model access is not enabled ... or the credentials lack bedrock:InvokeModel` | The role's ARN does not match the model or Region | `SENTINEL_AI_MODEL` must be `us.` + `bedrock_model_id`, and `SENTINEL_AWS_REGION` the account stack's `region` |
| `Bedrock rejected the request for this model` | The model is not offered on demand in that region | Use a model and region pair from the Bedrock console |
| `Bedrock is throttling this account` | New accounts start with low quotas | Wait a minute and retry |
| `AI quota reached` (in the app) | A daily bound was reached | Wait, or raise the bound in `.env` deliberately |
