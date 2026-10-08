"""Detection must not become a denial-of-service vector (ReDoS). Every rule runs against
adversarial inputs at the maximum inspected size and must stay fast; the bound is generous so
the test is stable on slow CI runners, while a catastrophic backtracking pattern would take
seconds or minutes."""

from __future__ import annotations

import time

import pytest

from app.security.http_analysis import MAX_BODY, MAX_QUERY, RULES

pytestmark = pytest.mark.security

ADVERSARIAL = [
    "union " + "/*" * (MAX_QUERY // 2),
    "union" + " /**/" * (MAX_QUERY // 5) + "x",
    "'" + " " * MAX_QUERY + "or",
    "' or " + "a" * MAX_QUERY,
    "<a " + "a" * MAX_BODY,
    "<" + "a " * (MAX_BODY // 2),
    "../" * (MAX_QUERY // 3),
    "$(" * (MAX_QUERY // 2),
    ";" + " " * MAX_QUERY,
    "http://" + "1." * (MAX_QUERY // 2),
    "x" * MAX_BODY,
    # Many possible starting points, each of which must fail fast.
    "<a" * (MAX_BODY // 2),
    "<a on" * (MAX_BODY // 5),
    "union/**/" * (MAX_QUERY // 9),
    "' ' " * (MAX_QUERY // 4),
    "/*" + "*" * MAX_QUERY,
    "union /*" + "a" * MAX_QUERY,
]


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.rule_id)
def test_rules_are_linear_on_adversarial_input(rule: object) -> None:
    pattern = rule.pattern  # type: ignore[attr-defined]
    worst = 0.0
    for text in ADVERSARIAL:
        start = time.perf_counter()
        pattern.search(text.lower())
        worst = max(worst, time.perf_counter() - start)
    assert worst < 0.5, f"{rule.rule_id} took {worst:.2f}s"  # type: ignore[attr-defined]
