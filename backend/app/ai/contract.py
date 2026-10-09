"""The AI output contract (OWASP LLM05, LLM06; ADR-0007, C-AI-02, C-AI-03, C-AI-05).

The model must answer with exactly one JSON object matching `AnalysisOutput`. The engine then
checks what a schema cannot:

* every `observed_evidence` item is a verbatim quote of a field that was actually sent, so the
  model cannot present an invention as a fact (inferences belong in `inference`);
* every proposed action is of a type allowed for this subject, at most one of each, and a WAF
  change request may only target the rule named by the platform and only to BLOCK (the AI can
  propose tightening a control, never loosening one);
* every control ID exists in SentinelEdge's catalogue.

Anything else is rejected with the reason, stored as a rejected analysis and shown as such.
Nothing is repaired: a "fixed up" answer is an answer nobody actually gave. The only tolerance
is one surrounding Markdown code fence, which models add by habit and which carries no content.
"""

from __future__ import annotations

import json
import re
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, ValidationError

from app.ai.guardrails import AnalysisInput
from app.models.ai import ProposalType
from app.models.security_event import Severity

MAX_OUTPUT_CHARS = 20_000
MIN_QUOTE = 4
_FENCE = re.compile(r"^```(?:json)?\s*\n(.*)\n```$", re.DOTALL)
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class Classification(StrEnum):
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    SSRF = "ssrf"
    CREDENTIAL_ATTACK = "credential_attack"
    AUTHORIZATION_ABUSE = "authorization_abuse"
    API_ABUSE = "api_abuse"
    RECONNAISSANCE = "reconnaissance"
    VULNERABLE_COMPONENT = "vulnerable_component"
    CODE_WEAKNESS = "code_weakness"
    EXPOSED_SECRET = "exposed_secret"  # noqa: S105 - a classification name  # nosec B105
    DESIGN_THREAT = "design_threat"
    BENIGN = "benign"
    UNKNOWN = "unknown"


class ContractError(ValueError):
    """The answer broke the contract. The message is ours, safe to store and show."""


def _plain(value: str) -> str:
    if _CONTROL.search(value):
        raise ValueError("must not contain control characters")
    return value.strip()


Plain = AfterValidator(_plain)
ControlRef = Annotated[str, Field(pattern=r"^C-[A-Z]+-[0-9]{2}$")]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class Evidence(_Strict):
    field: Annotated[str, Field(pattern=r"^[a-z0-9_.]{1,40}$")]
    quote: Annotated[str, Field(min_length=MIN_QUOTE, max_length=300), Plain]


class Recommendation(_Strict):
    text: Annotated[str, Field(min_length=10, max_length=300), Plain]
    controls: Annotated[list[ControlRef], Field(max_length=5)] = Field(default_factory=list)


Rationale = Annotated[str, Field(min_length=20, max_length=600), Plain]


class OpenIncident(_Strict):
    type: Literal["open_incident"]
    title: Annotated[str, Field(min_length=5, max_length=160), Plain]
    severity: Severity
    rationale: Rationale


class RaiseChangeRequest(_Strict):
    type: Literal["raise_change_request"]
    rule_id: Annotated[str, Field(pattern=r"^[A-Z]{2,8}-[0-9]{3}$")]
    mode: Literal["block"]  # the AI may propose tightening a control, never loosening one
    rationale: Rationale


class AddThreat(_Strict):
    type: Literal["add_threat"]
    title: Annotated[str, Field(min_length=5, max_length=300), Plain]
    stride: Annotated[str, Field(pattern=r"^[STRIDE](/[STRIDE]){0,5}$")]
    likelihood: Annotated[int, Field(ge=1, le=3)]
    impact: Annotated[int, Field(ge=1, le=3)]
    controls: Annotated[list[ControlRef], Field(min_length=1, max_length=5)]
    rationale: Rationale


Action = Annotated[OpenIncident | RaiseChangeRequest | AddThreat, Field(discriminator="type")]


class AnalysisOutput(_Strict):
    summary: Annotated[str, Field(min_length=10, max_length=600), Plain]
    classification: Classification
    severity: Severity
    confidence: Annotated[float, Field(ge=0.0, le=1.0)]
    observed_evidence: Annotated[list[Evidence], Field(min_length=1, max_length=8)]
    inference: Annotated[str, Field(min_length=10, max_length=1500), Plain]
    recommendations: Annotated[list[Recommendation], Field(max_length=5)] = Field(
        default_factory=list
    )
    proposed_actions: Annotated[list[Action], Field(max_length=3)] = Field(default_factory=list)


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ContractError("the answer repeats a key")
    return dict(pairs)


def _reject_constant(name: str) -> Any:
    raise ContractError(f"the answer contains {name}, which is not JSON")


def parse(text: str) -> AnalysisOutput:
    """Parse the raw answer into the schema, or raise ContractError."""
    if len(text) > MAX_OUTPUT_CHARS:
        raise ContractError("the answer is too long")
    body = text.strip()
    if fenced := _FENCE.match(body):
        body = fenced.group(1).strip()
    if not body.startswith("{"):
        raise ContractError("the answer is not a single JSON object")
    try:
        data = json.loads(
            body, object_pairs_hook=_no_duplicate_keys, parse_constant=_reject_constant
        )
    except json.JSONDecodeError as exc:
        raise ContractError(f"the answer is not valid JSON (line {exc.lineno})") from None
    if not isinstance(data, dict):
        raise ContractError("the answer is not a single JSON object")
    try:
        # Strict JSON-mode validation: no type coercion beyond what JSON itself means.
        return AnalysisOutput.model_validate_json(json.dumps(data))
    except ValidationError as exc:
        first = exc.errors()[0]
        where = ".".join(str(p) for p in first["loc"]) or "answer"
        raise ContractError(f"{where}: {first['msg']}") from None


def check(output: AnalysisOutput, inp: AnalysisInput, known_controls: frozenset[str]) -> None:
    """The checks a schema cannot express. Raises ContractError on the first problem."""
    for n, item in enumerate(output.observed_evidence):
        value = inp.fields.get(item.field)
        if value is None:
            raise ContractError(
                f"observed_evidence[{n}] cites a field that was not in the data ({item.field})"
            )
        if item.quote not in value:
            raise ContractError(f"observed_evidence[{n}] is not a verbatim quote of {item.field}")
    seen: set[str] = set()
    for n, action in enumerate(output.proposed_actions):
        kind = ProposalType(action.type)
        if kind not in inp.allowed_actions:
            raise ContractError(f"proposed_actions[{n}]: {kind} is not allowed here")
        if kind in seen:
            raise ContractError(f"proposed_actions[{n}]: more than one {kind}")
        seen.add(kind)
        if isinstance(action, RaiseChangeRequest) and action.rule_id != inp.waf_rule:
            raise ContractError(
                f"proposed_actions[{n}]: only rule {inp.waf_rule} may be changed here"
            )
    cited = {c for r in output.recommendations for c in r.controls}
    cited |= {c for a in output.proposed_actions if isinstance(a, AddThreat) for c in a.controls}
    unknown = sorted(cited - known_controls)
    if unknown:
        raise ContractError(f"unknown control IDs: {', '.join(unknown[:5])}")


def validate(text: str, inp: AnalysisInput, known_controls: frozenset[str]) -> AnalysisOutput:
    output = parse(text)
    check(output, inp, known_controls)
    return output
