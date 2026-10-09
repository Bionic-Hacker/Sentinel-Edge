"""The offline analyser: a deterministic stand-in for a model (ADR-0006).

It answers from the platform's own verdict and the fields it was given, never from the text
inside them, so it cannot be steered by prompt injection, costs nothing and gives the same
answer every time. It exists so the whole engine (guardrails, contract, proposals, approval,
the UI) can be built, tested and demonstrated without calling a paid model. Its answers go
through exactly the same parsing and validation as a real model's.
"""

from __future__ import annotations

import json
from typing import Any

from app.ai.guardrails import AnalysisInput
from app.models.ai import ProposalType, SubjectType

# Platform category -> (classification, controls that address it; all in the catalogue).
_BY_CATEGORY: dict[str, tuple[str, tuple[str, ...]]] = {
    "sql_injection": ("sql_injection", ("C-API-04", "C-SO-02", "C-WAF-01")),
    "xss": ("xss", ("C-WEB-02", "C-SO-09", "C-WAF-01")),
    "path_traversal": ("path_traversal", ("C-API-04", "C-SO-02")),
    "command_injection": ("command_injection", ("C-API-04", "C-SO-02")),
    "ssrf": ("ssrf", ("C-API-12", "C-SO-02")),
    "scanner": ("reconnaissance", ("C-API-03", "C-SO-02")),
    "recon": ("reconnaissance", ("C-API-03", "C-SO-02")),
    "bot": ("reconnaissance", ("C-API-03", "C-WAF-03")),
    "auth_failure": ("credential_attack", ("C-ID-04", "C-ID-05", "C-API-03")),
    "brute_force": ("credential_attack", ("C-ID-04", "C-ID-05", "C-API-03")),
    "credential_stuffing": ("credential_attack", ("C-ID-04", "C-ID-05", "C-WAF-03")),
    "suspicious_auth": ("credential_attack", ("C-ID-04", "C-ID-03")),
    "token_theft": ("credential_attack", ("C-ID-03", "C-ID-04")),
    "bola": ("authorization_abuse", ("C-API-01", "C-SO-04")),
    "bfla": ("authorization_abuse", ("C-API-02", "C-SO-04")),
    "privilege_change": ("authorization_abuse", ("C-API-02", "C-AUD-01")),
    "rate_limit": ("api_abuse", ("C-API-03",)),
    "api_abuse": ("api_abuse", ("C-API-03", "C-SO-04")),
    "audit_tampering": ("authorization_abuse", ("C-AUD-01",)),
    "vulnerable_dependency": ("vulnerable_component", ("C-VM-01", "C-CICD-08")),
    "code_weakness": ("code_weakness", ("C-VM-01", "C-CICD-08")),
    "exposed_secret": ("exposed_secret", ("C-SEC-01", "C-VM-01")),
}
_FALLBACK = ("unknown", ("C-SO-02",))

# A missing STRIDE letter in a model -> a generic threat to suggest, with its controls.
_STRIDE_GAPS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (
        "S",
        "Attacker impersonates a legitimate user with stolen or guessed credentials",
        ("C-ID-04", "C-ID-05"),
    ),
    ("T", "Request input tampers with stored data or queries", ("C-API-04",)),
    ("R", "Actions cannot be traced to who performed them", ("C-AUD-01",)),
    ("I", "Responses expose more data than the caller may see", ("C-API-01", "C-API-06")),
    ("D", "Request floods exhaust the service", ("C-API-03",)),
    ("E", "A user reaches functions beyond their role", ("C-API-02",)),
)

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _quote(inp: AnalysisInput, field: str) -> dict[str, str] | None:
    value = inp.fields.get(field, "")
    if len(value) < 4:
        return None
    return {"field": field, "quote": value[:120]}


def _evidence(inp: AnalysisInput, preferred: tuple[str, ...]) -> list[dict[str, str]]:
    found = [q for f in preferred if (q := _quote(inp, f))]
    if not found:  # any field long enough to quote
        found = [q for f in inp.fields if (q := _quote(inp, f))][:1]
    return found[:6]


def analyse(inp: AnalysisInput) -> dict[str, Any]:
    p = inp.platform
    category = p.get("category", "")
    classification, controls = _BY_CATEGORY.get(category, _FALLBACK)
    severity = p.get("severity", "medium")
    actions: list[dict[str, Any]] = []

    if inp.subject_type is SubjectType.SECURITY_EVENT:
        evidence = _evidence(
            inp, ("title", "evidence.snippet", "endpoint", "rule_id", "user_agent", "outcome")
        )
        where = inp.fields.get("endpoint", "the platform")
        summary = f"{inp.fields.get('title', 'A security event')} at {where}."
        inference = (
            f"The pattern is consistent with {classification.replace('_', ' ')}. The request "
            f"outcome was {inp.fields.get('outcome', 'unknown')}, so the controls listed below "
            "are what stood between it and the application."
        )
        if (
            ProposalType.OPEN_INCIDENT in inp.allowed_actions
            and _SEVERITY_RANK.get(severity, 0) >= _SEVERITY_RANK["high"]
        ):
            actions.append(
                {
                    "type": "open_incident",
                    "title": f"Investigate {classification.replace('_', ' ')} at {where}"[:160],
                    "severity": severity,
                    "rationale": "A high-severity detection that no incident tracks yet.",
                }
            )
        if ProposalType.RAISE_CHANGE_REQUEST in inp.allowed_actions and inp.waf_rule:
            actions.append(
                {
                    "type": "raise_change_request",
                    "rule_id": inp.waf_rule,
                    "mode": "block",
                    "rationale": f"The simulated WAF rule {inp.waf_rule} only counted this "
                    "request; blocking stops the pattern at the edge.",
                }
            )
    elif inp.subject_type is SubjectType.INCIDENT:
        evidence = _evidence(inp, ("title", "summary", "detection_rule", "event_1.title"))
        summary = f"{inp.subject_ref}: {inp.fields.get('title', 'an incident')}."
        inference = (
            f"The linked evidence points to {classification.replace('_', ' ')}. Severity "
            f"{severity}; status {inp.fields.get('status', 'unknown')}."
        )
    elif inp.subject_type is SubjectType.VULNERABILITY:
        evidence = _evidence(inp, ("title", "component", "cve", "fixed_version", "location"))
        fix = inp.fields.get("fixed_version")
        summary = f"{inp.fields.get('title', 'A finding')} in {inp.fields.get('component', '?')}."
        inference = (
            f"A fix is published ({fix}); upgrading closes the finding at the next scan."
            if fix
            else "No fix is published; reduce exposure and track the upstream release."
        )
    else:  # threat model
        evidence = _evidence(inp, ("name", "scope", "assets", "threats"))
        summary = f"{inp.subject_ref}: {inp.fields.get('name', 'a threat model')}."
        covered = set(inp.fields.get("stride_covered", ""))
        gap = next((g for g in _STRIDE_GAPS if g[0] not in covered), None)
        classification, controls = "design_threat", ("C-API-01", "C-API-02")
        inference = (
            f"No threat in the model covers STRIDE category {gap[0]}."
            if gap
            else "Every STRIDE category has at least one threat in the model."
        )
        if gap and ProposalType.ADD_THREAT in inp.allowed_actions:
            actions.append(
                {
                    "type": "add_threat",
                    "title": gap[1],
                    "stride": gap[0],
                    "likelihood": 2,
                    "impact": 2,
                    "controls": list(gap[2]),
                    "rationale": f"The model has no threat in STRIDE category {gap[0]}.",
                }
            )

    return {
        "summary": summary[:600] if len(summary) >= 10 else f"{summary} (analysed).",
        "classification": classification,
        "severity": severity,
        "confidence": 0.6,
        "observed_evidence": evidence,
        "inference": inference,
        "recommendations": [
            {
                "text": "Confirm these controls are in place and producing evidence.",
                "controls": list(controls),
            }
        ],
        "proposed_actions": actions,
    }


def answer(inp: AnalysisInput) -> str:
    return json.dumps(analyse(inp), ensure_ascii=False)
