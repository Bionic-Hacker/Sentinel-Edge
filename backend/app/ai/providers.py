"""AI providers behind one interface (ADR-0006).

`SENTINEL_AI_PROVIDER` selects one:
* `disabled` (the default): the engine refuses to run (503 `ai_disabled`); nothing is sent.
* `offline`: the deterministic analyser in app.ai.offline. Free, local, refused in production.
* `bedrock`: Amazon Bedrock (app.ai.bedrock), the only provider that costs money.

A provider only turns a prompt into text. Everything that keeps the engine safe (minimising,
scoring, delimiting, validating, quotas, audit) happens around it, identically for each one.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from app.ai import offline
from app.ai.guardrails import AnalysisInput, Prompt, estimate_tokens
from app.core.config import AIProvider, Settings


@dataclass(frozen=True)
class Completion:
    text: str
    input_tokens: int
    output_tokens: int


class ProviderError(Exception):
    """The provider did not produce an answer. The message is ours, safe to store and show."""


class Provider(Protocol):
    name: str
    model: str

    def complete(self, prompt: Prompt, inp: AnalysisInput, max_tokens: int) -> Completion: ...


class OfflineProvider:
    name = "offline"
    model = "sentineledge-offline-1"

    def complete(self, prompt: Prompt, inp: AnalysisInput, max_tokens: int) -> Completion:
        text = offline.answer(inp)
        return Completion(
            text=text,
            input_tokens=estimate_tokens(prompt.system + prompt.user),
            output_tokens=min(max_tokens, estimate_tokens(text)),
        )


def get_provider(settings: Settings) -> Provider | None:
    """The configured provider, or None when AI is disabled."""
    if settings.ai_provider is AIProvider.OFFLINE:
        return OfflineProvider()
    if settings.ai_provider is AIProvider.BEDROCK:
        # Imported here so boto3 loads only when Bedrock is the provider.
        from app.ai.bedrock import BedrockProvider

        return BedrockProvider(settings)
    return None
