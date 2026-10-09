"""The posture score's categories must cover every control family in the catalogue exactly
once, so a new family cannot silently drop out of the score (ADR-0022)."""

from __future__ import annotations

import json
from collections import Counter

from app.services.governance import CATALOGUE_PATH
from app.services.posture import CATEGORIES, METHOD


def test_every_control_family_belongs_to_exactly_one_category() -> None:
    families = {c["family"] for c in json.loads(CATALOGUE_PATH.read_text())["controls"]}
    owners = Counter(f for _, _, fams in CATEGORIES for f in fams)
    assert set(owners) >= families, sorted(families - set(owners))
    assert all(n == 1 for n in owners.values())
    assert len({key for key, _, _ in CATEGORIES}) == len(CATEGORIES)


def test_the_method_is_published_with_the_score() -> None:
    for phrase in ("coverage", "past their SLA", "open live incidents", "planned"):
        assert phrase in METHOD
