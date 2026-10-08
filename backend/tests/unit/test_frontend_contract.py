"""The SPA validates every API response against its own lists of allowed values
(frontend/src/lib/types.ts). A value the backend can send but the SPA does not list makes a whole
page fail to load, as `appsec` events did after Phase 8 M2, so the two must agree exactly."""

from __future__ import annotations

import re
from enum import StrEnum
from pathlib import Path

import pytest

from app.core.provenance import Provenance
from app.models.incident import IncidentStatus
from app.models.security_event import EventCategory, EventSource, Outcome, Severity
from app.models.user import Role
from app.models.vulnerability import (
    AcceptanceEnd,
    FindingCategory,
    ScanSource,
    ScanTool,
    VulnStatus,
)

TYPES_TS = Path(__file__).resolve().parents[3] / "frontend" / "src" / "lib" / "types.ts"

CONTRACT: dict[str, type[StrEnum]] = {
    "PROVENANCES": Provenance,
    "ROLES": Role,
    "SEVERITIES": Severity,
    "EVENT_SOURCES": EventSource,
    "EVENT_CATEGORIES": EventCategory,
    "OUTCOMES": Outcome,
    "INCIDENT_STATUSES": IncidentStatus,
    "VULN_STATUSES": VulnStatus,
    "FINDING_CATEGORIES": FindingCategory,
    "SCAN_TOOLS": ScanTool,
    "SCAN_SOURCES": ScanSource,
    "ACCEPTANCE_ENDS": AcceptanceEnd,
}


def frontend_list(source: str, name: str) -> set[str]:
    match = re.search(rf"export const {name} = \[(.*?)\] as const", source, re.S)
    assert match, f"{name} not found in types.ts"
    return set(re.findall(r'"([^"]+)"', match.group(1)))


@pytest.mark.skipif(not TYPES_TS.exists(), reason="frontend sources not present")
@pytest.mark.parametrize("name", sorted(CONTRACT))
def test_frontend_lists_match_the_backend_enumerations(name: str) -> None:
    expected = {member.value for member in CONTRACT[name]}
    assert frontend_list(TYPES_TS.read_text(), name) == expected
