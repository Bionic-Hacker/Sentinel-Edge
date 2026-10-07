"""The OWASP API Top 10 coverage claims stay honest: every cited test exists."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.core.api_policy import ENDPOINTS, OwaspApi
from app.core.owasp_coverage import COVERAGE, CoverageStatus

pytestmark = pytest.mark.security
BACKEND = Path(__file__).resolve().parents[2]


def test_all_ten_categories_once_in_order() -> None:
    assert [c.category for c in COVERAGE] == list(OwaspApi)


@pytest.mark.parametrize("coverage", COVERAGE, ids=lambda c: c.category.code)
def test_cited_evidence_exists(coverage: object) -> None:
    for ref in coverage.evidence:  # type: ignore[attr-defined]
        path, _, test_name = ref.partition("::")
        source = BACKEND / path
        assert source.is_file(), f"missing evidence file {path}"
        assert re.search(rf"^def {re.escape(test_name)}\(", source.read_text(), re.M), ref


def test_incomplete_categories_say_what_completes_them() -> None:
    for c in COVERAGE:
        assert c.controls
        assert c.evidence
        if c.status is not CoverageStatus.MITIGATED:
            assert c.planned, f"{c.category.code} needs a planned completion"


def test_endpoint_exposure_is_covered() -> None:
    exposed = {category for policy in ENDPOINTS.values() for category in policy.owasp}
    not_exposed = {c.category for c in COVERAGE if c.status is CoverageStatus.NOT_EXPOSED}
    # A category marked "not exposed" must not be named as an exposure of any endpoint.
    assert exposed & not_exposed == set()
