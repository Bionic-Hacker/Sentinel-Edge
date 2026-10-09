# Amazon Bedrock for the AI engine (Phase 9)

The AI engine runs without AWS: `SENTINEL_AI_PROVIDER=offline` is a deterministic local
analyser that goes through exactly the same guardrails, contract and approval workflow, at no
cost. This page is for when you want a real model to answer. It is the only part of SentinelEdge
before the AWS window (Phases 3 to 5) that touches AWS, and it creates no infrastructure: on-demand
model calls only ([ADR-0006](adr/0006-amazon-bedrock-ai-provider.md)).

## What it costs

The default model is **Amazon Nova Micro** (`amazon.nova-micro-v1:0`), about $0.035 per million
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

**1. A budget alert.** In the AWS console, *Billing and Cost Management → Budgets*, create a
monthly cost budget of $1 with an e-mail alert. (On a new account this is also one of the tasks
that earns credits.)

**2. An IAM user that can do exactly one thing.** *IAM → Users → Create user*
`sentineledge-bedrock`, no console access. Attach this inline policy, and nothing else:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "InvokeNovaMicroOnly",
      "Effect": "Allow",
      "Action": "bedrock:InvokeModel",
      "Resource": "arn:aws:bedrock:us-east-1::foundation-model/amazon.nova-micro-v1:0"
    }
  ]
}
```

The Converse API the engine uses is authorised by `bedrock:InvokeModel`. A different model or
region needs its own ARN here, and nothing else in the account is reachable with these keys.
Amazon models are enabled by default in commercial regions; no Marketplace subscription is
involved.

**3. An access key for the AWS CLI.** On the user, *Security credentials → Create access key →
Command Line Interface*. Then, on your machine (fish):

```fish
sudo pacman -S aws-cli-v2
aws configure --profile sentineledge-bedrock
# AWS Access Key ID / Secret Access Key: from the step above
# Default region name: us-east-1
# Default output format: json
```

These long-lived keys stay in `~/.aws` on your machine. They never enter a container: the next
step exchanges them for a session that expires.

## Each time you want Bedrock

```fish
cd ~/Sentinel-Edge/sentineledge
make bedrock-credentials          # writes .env.bedrock: an 8-hour session (HOURS=1..12)
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
Provider bedrock, model amazon.nova-micro-v1:0
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
When Phase 9 is over, delete the IAM user's access key in the console if you no longer need it.

## Troubleshooting

| `make ai-check` says | Cause | Fix |
|---|---|---|
| `No AWS credentials` | `.env.bedrock` missing, or the API was not reloaded | `make bedrock-credentials`, then `docker compose up -d api` |
| `The AWS session credentials have expired` | The session passed its expiry | `make bedrock-credentials` again |
| `model access is not enabled ... or the credentials lack bedrock:InvokeModel` | The policy's ARN does not match the model or region | Compare the policy with `SENTINEL_AI_MODEL` and `SENTINEL_AWS_REGION` |
| `Bedrock rejected the request for this model` | The model is not offered on demand in that region | Use a model and region pair from the Bedrock console |
| `Bedrock is throttling this account` | New accounts start with low quotas | Wait a minute and retry |
| `AI quota reached` (in the app) | A daily bound was reached | Wait, or raise the bound in `.env` deliberately |
