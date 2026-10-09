"""Amazon Bedrock provider (ADR-0006, ADR-0024). The only part of the engine that costs money.

* **Model:** `SENTINEL_AI_MODEL`, Amazon Nova Micro by default: an AWS model, so new-account
  credits apply, and the cheapest that meets the contract. Anthropic models work the same way
  (the Converse API is model-neutral) but are billed through AWS Marketplace.
* **Credentials:** the standard AWS chain. Deployed, that is the ECS task role, scoped to
  `bedrock:InvokeModel` on the one model (no key exists to leak). Locally, short-lived session
  credentials written by `make bedrock-credentials`; nothing long-lived enters the container.
* **Network:** the client talks only to `bedrock-runtime.<region>.amazonaws.com`. Region and
  model come from validated settings, never from a request, so there is no SSRF surface.
* **Bounds:** `maxTokens` from settings, temperature 0, connect and read timeouts, two attempts.
  An answer cut off at the token limit is a failure, not a partial answer.

Errors become ProviderError with our own wording; AWS's messages (which can name account IDs
and ARNs) go to the log, not to the user or the database.
"""

from __future__ import annotations

import logging
from functools import cache
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

from app.ai.guardrails import AnalysisInput, Prompt
from app.ai.providers import Completion, ProviderError
from app.core.config import Settings

log = logging.getLogger(__name__)

_CLIENT_ERRORS = {
    "AccessDeniedException": "Bedrock refused the call: model access is not enabled for this "
    "account and region, or the credentials lack bedrock:InvokeModel on this model.",
    "ValidationException": "Bedrock rejected the request for this model (check SENTINEL_AI_MODEL "
    "and the region).",
    "ThrottlingException": "Bedrock is throttling this account; try again shortly.",
    "ServiceQuotaExceededException": "The account's Bedrock quota is exhausted.",
    "ModelNotReadyException": "The model is not ready in this region yet.",
    "ExpiredTokenException": "The AWS session credentials have expired: run "
    "`make bedrock-credentials` again.",
    "UnrecognizedClientException": "AWS did not recognise the credentials.",
}


@cache
def _client(region: str, timeout: int) -> Any:
    return boto3.client(
        "bedrock-runtime",
        region_name=region,
        config=Config(
            connect_timeout=5,
            read_timeout=timeout,
            retries={"max_attempts": 2, "mode": "standard"},
            user_agent_extra="sentineledge",
        ),
    )


class BedrockProvider:
    name = "bedrock"

    def __init__(self, settings: Settings, client: Any = None) -> None:
        self.model = settings.ai_model
        self._client = client or _client(settings.aws_region, settings.ai_timeout_seconds)

    def complete(self, prompt: Prompt, inp: AnalysisInput, max_tokens: int) -> Completion:
        try:
            response = self._client.converse(
                modelId=self.model,
                system=[{"text": prompt.system}],
                messages=[{"role": "user", "content": [{"text": prompt.user}]}],
                inferenceConfig={"maxTokens": max_tokens, "temperature": 0.0},
            )
        except NoCredentialsError:
            raise ProviderError(
                "No AWS credentials: run `make bedrock-credentials` (local) or attach the task "
                "role (deployed)."
            ) from None
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            log.warning("bedrock call failed", extra={"aws_error": code, "model": self.model})
            raise ProviderError(
                _CLIENT_ERRORS.get(code, f"Bedrock returned an error ({code or 'unknown'}).")
            ) from None
        except BotoCoreError as exc:
            log.warning("bedrock call failed", extra={"aws_error": type(exc).__name__})
            raise ProviderError("Bedrock could not be reached in time.") from None

        usage = response.get("usage") or {}
        if response.get("stopReason") == "max_tokens":
            raise ProviderError(
                f"The answer was cut off at the {max_tokens}-token limit "
                "(SENTINEL_AI_MAX_OUTPUT_TOKENS)."
            )
        try:
            blocks = response["output"]["message"]["content"]
            text = "".join(b["text"] for b in blocks if "text" in b)
        except (KeyError, TypeError):
            raise ProviderError("Bedrock returned a response without text.") from None
        return Completion(
            text=text,
            input_tokens=int(usage.get("inputTokens", 0)),
            output_tokens=int(usage.get("outputTokens", 0)),
        )
