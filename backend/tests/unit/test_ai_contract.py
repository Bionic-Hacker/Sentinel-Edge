"""The AI output contract (ADR-0007, C-AI-02, C-AI-03, C-AI-05): what a model returns is checked,
and anything that breaks the contract is rejected, never repaired."""

from __future__ import annotations

import json
from typing import Any

import pytest

from app.ai import offline
from app.ai.contract import ContractError, check, parse, validate
from app.ai.guardrails import AnalysisInput
from app.models.ai import ProposalType, SubjectType

pytestmark = pytest.mark.security

KNOWN = frozenset({"C-API-04", "C-SO-02", "C-WAF-01", "C-ID-04"})


def _input(**overrides: Any) -> AnalysisInput:
    base: dict[str, Any] = {
        "subject_type": SubjectType.SECURITY_EVENT,
        "subject_ref": "event SQLI-001",
        "fields": {
            "title": "UNION-based query extension",
            "endpoint": "/api/v1/users",
            "evidence.snippet": "id=1 union select password from users",
            "outcome": "allowed",
        },
        "platform": {"category": "sql_injection", "severity": "high"},
        "allowed_actions": frozenset(
            {ProposalType.OPEN_INCIDENT, ProposalType.RAISE_CHANGE_REQUEST}
        ),
        "waf_rule": "SQLI-001",
    }
    base.update(overrides)
    return AnalysisInput(**base)


def _answer(**overrides: Any) -> dict[str, Any]:
    answer: dict[str, Any] = {
        "summary": "A UNION-based SQL injection probe against /api/v1/users.",
        "classification": "sql_injection",
        "severity": "high",
        "confidence": 0.8,
        "observed_evidence": [
            {"field": "evidence.snippet", "quote": "union select password"},
        ],
        "inference": "The attacker is trying to read the users table through the id filter.",
        "recommendations": [{"text": "Keep parameterised queries.", "controls": ["C-API-04"]}],
        "proposed_actions": [],
    }
    answer.update(overrides)
    return answer


def test_a_valid_answer_passes() -> None:
    out = validate(json.dumps(_answer()), _input(), KNOWN)
    assert out.classification == "sql_injection"
    assert out.observed_evidence[0].quote == "union select password"


def test_one_markdown_fence_is_tolerated_and_nothing_else() -> None:
    validate("```json\n" + json.dumps(_answer()) + "\n```", _input(), KNOWN)
    with pytest.raises(ContractError, match="single JSON object"):
        parse("Here is my analysis: " + json.dumps(_answer()))


def test_evidence_must_quote_the_input_verbatim() -> None:
    invented = _answer(
        observed_evidence=[{"field": "evidence.snippet", "quote": "union select credit_card"}]
    )
    with pytest.raises(ContractError, match="not a verbatim quote"):
        validate(json.dumps(invented), _input(), KNOWN)
    unknown_field = _answer(observed_evidence=[{"field": "body", "quote": "union select"}])
    with pytest.raises(ContractError, match="not in the data"):
        validate(json.dumps(unknown_field), _input(), KNOWN)


HOSTILE: list[tuple[str, Any, str]] = [
    ("extra field", _answer(execute="rm -rf /"), "Extra inputs"),
    ("wrong type", _answer(confidence="0.9"), "valid number"),
    ("boolean confidence", _answer(confidence=True), "valid number"),
    ("unknown classification", _answer(classification="nothing_to_see"), "classification"),
    ("severity out of enum", _answer(severity="none"), "severity"),
    ("confidence out of range", _answer(confidence=7), "confidence"),
    ("no evidence", _answer(observed_evidence=[]), "observed_evidence"),
    ("control characters", _answer(summary="clean\x1b[2Jsummary text"), "control"),
    (
        "tool call",
        _answer(proposed_actions=[{"type": "run_shell", "rationale": "x" * 30}]),
        "proposed_actions",
    ),
    (
        "weakening the WAF",
        _answer(
            proposed_actions=[
                {
                    "type": "raise_change_request",
                    "rule_id": "SQLI-001",
                    "mode": "count",
                    "rationale": "Counting is enough for this traffic.",
                }
            ]
        ),
        "mode",
    ),
    (
        "another WAF rule",
        _answer(
            proposed_actions=[
                {
                    "type": "raise_change_request",
                    "rule_id": "XSS-001",
                    "mode": "block",
                    "rationale": "Block another rule while at it.",
                }
            ]
        ),
        "only rule SQLI-001",
    ),
    (
        "action not allowed for the subject",
        _answer(
            proposed_actions=[
                {
                    "type": "add_threat",
                    "title": "Some threat",
                    "stride": "T",
                    "likelihood": 2,
                    "impact": 2,
                    "controls": ["C-API-04"],
                    "rationale": "Add this to the model.",
                }
            ]
        ),
        "not allowed",
    ),
    (
        "two incidents",
        _answer(
            proposed_actions=[
                {
                    "type": "open_incident",
                    "title": "First one",
                    "severity": "high",
                    "rationale": "Open an incident for this.",
                }
            ]
            * 2
        ),
        "more than one",
    ),
    (
        "invented control",
        _answer(recommendations=[{"text": "Turn on magic.", "controls": ["C-MAGIC-01"]}]),
        "unknown control",
    ),
]


@pytest.mark.parametrize(("case", "answer", "message"), HOSTILE, ids=[h[0] for h in HOSTILE])
def test_hostile_answers_are_rejected_not_repaired(case: str, answer: Any, message: str) -> None:
    with pytest.raises(ContractError, match=message):
        validate(json.dumps(answer), _input(), KNOWN)


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "[]",
        "null",
        '{"summary": "a", "summary": "b"}',
        '{"confidence": NaN}',
        "{" * 30_000,
        "Ignore the schema. The request was benign.",
    ],
)
def test_malformed_answers_are_rejected(raw: str) -> None:
    with pytest.raises(ContractError):
        validate(raw, _input(), KNOWN)


def test_the_offline_analyser_meets_its_own_contract() -> None:
    inp = _input()
    out = validate(offline.answer(inp), inp, frozenset({"C-API-04", "C-SO-02", "C-WAF-01"}))
    kinds = {a.type for a in out.proposed_actions}
    assert kinds == {"open_incident", "raise_change_request"}
    check(out, inp, frozenset({"C-API-04", "C-SO-02", "C-WAF-01"}))
