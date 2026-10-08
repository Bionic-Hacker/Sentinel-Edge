"""Vulnerability management models (spec §19, §20).

Two directions:
* Import: what `make scan-import` sends (the gate's findings.json and the Syft SBOMs). Scanner
  output is text written by third parties (package metadata, rule messages, URLs), so every
  string is bounded and control characters are replaced; enumerations are checked, not trusted.
* API: what the vulnerability, scan and SBOM endpoints return and accept.
"""

from __future__ import annotations

import re
import uuid
from datetime import date, datetime
from typing import Annotated, Any

from pydantic import AfterValidator, BaseModel, BeforeValidator, Field

from app.models.security_event import Severity
from app.models.vulnerability import (
    AcceptanceEnd,
    FindingCategory,
    ScanSource,
    ScanTool,
    VulnStatus,
)
from app.schemas.applications import _text
from app.schemas.auth import StrictModel

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")

MAX_FINDINGS = 20_000
MAX_SBOM_COMPONENTS = 20_000


def _bounded(size: int) -> BeforeValidator:
    """Scanner text: coerce to str, replace control characters, clip to the column size."""

    def clean(value: Any) -> Any:
        if value is None:
            return None
        return _CONTROL.sub("?", str(value))[:size]

    return BeforeValidator(clean)


def _references(value: Any) -> Any:
    if not isinstance(value, list):
        return []
    return [_CONTROL.sub("?", str(v))[:500] for v in value[:10]]


# --- Import -------------------------------------------------------------------------------------


class ImportedFinding(BaseModel):
    """One normalised finding (app.scanning.findings.Finding.to_dict)."""

    tool: ScanTool
    category: FindingCategory
    rule_id: Annotated[str, _bounded(200), Field(min_length=1)]
    title: Annotated[str, _bounded(300), Field(min_length=1)]
    severity: Severity
    component: Annotated[str, _bounded(500)]
    location: Annotated[str, _bounded(500)]
    fingerprint: Annotated[str, Field(pattern=r"^[0-9a-f]{32,64}$")]
    cve: Annotated[str | None, _bounded(32)] = None
    cvss: Annotated[float | None, Field(ge=0, le=10)] = None
    fixed_version: Annotated[str | None, _bounded(100)] = None
    recommendation: Annotated[str | None, _bounded(1000)] = None
    references: Annotated[list[str], BeforeValidator(_references)] = Field(default_factory=list)

    @property
    def is_package_vulnerability(self) -> bool:
        return self.category in {FindingCategory.SCA, FindingCategory.CONTAINER} and bool(self.cve)

    @property
    def fixable(self) -> bool:
        return not self.is_package_vulnerability or bool(self.fixed_version)


class ScanReport(BaseModel):
    """The gate's findings.json."""

    generated_at: datetime
    reports: Annotated[
        list[Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}\.json$")]],
        Field(min_length=1, max_length=20),
    ]
    passed: bool
    findings: Annotated[list[ImportedFinding], Field(max_length=MAX_FINDINGS)]


# --- API: findings --------------------------------------------------------------------------------


class AppRef(BaseModel):
    id: uuid.UUID
    slug: str
    name: str


class ScanRef(BaseModel):
    id: uuid.UUID
    reference: str
    imported_at: datetime


class AcceptanceOut(BaseModel):
    id: uuid.UUID
    reference: str
    justification: str
    compensating_control: str
    approver_label: str
    created_at: datetime
    expires_at: datetime
    ended_at: datetime | None
    end_reason: AcceptanceEnd | None
    ended_by_label: str | None
    in_force: bool


class VulnerabilitySummary(BaseModel):
    id: uuid.UUID
    reference: str
    application: AppRef
    tool: ScanTool
    category: FindingCategory
    rule_id: str
    title: str
    severity: Severity
    component: str
    location: str
    cve: str | None
    fixed_version: str | None
    fixable: bool
    status: VulnStatus
    first_seen_at: datetime
    last_seen_at: datetime
    resolved_at: datetime | None
    sla_due_at: datetime | None
    overdue: bool
    times_reopened: int
    version: int


class VulnerabilityDetail(VulnerabilitySummary):
    cvss: float | None
    recommendation: str | None
    references: list[str]
    status_note: str | None
    first_scan: ScanRef
    last_scan: ScanRef
    acceptances: list[AcceptanceOut]
    # What the caller may do, decided by the server (the UI never re-derives the rules).
    allowed_statuses: list[VulnStatus]
    can_accept_risk: bool
    can_revoke_acceptance: bool
    max_acceptance_days: int


class VulnerabilityPage(BaseModel):
    items: list[VulnerabilitySummary]
    next_before: int | None


class SeverityCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class LastScan(BaseModel):
    id: uuid.UUID
    reference: str
    application: AppRef
    source: ScanSource
    imported_at: datetime
    generated_at: datetime
    commit_sha: str | None
    gate_passed: bool


class VulnerabilityOverview(BaseModel):
    """Counts for the dashboard and the Vulnerabilities page."""

    active: SeverityCounts  # open or in progress
    active_total: int
    awaiting_fix: int  # active package vulnerabilities with no fixed version published
    overdue: int  # active and past the SLA due date
    accepted: int
    false_positive: int
    fixed_30d: int
    by_category: dict[str, int]
    last_scan: LastScan | None


Note = Annotated[str, Field(max_length=2000), AfterValidator(_text)]
Justification = Annotated[str, Field(min_length=20, max_length=2000), AfterValidator(_text)]


class StatusChange(StrictModel):
    status: VulnStatus
    note: Note | None = None
    version: Annotated[int, Field(ge=1, le=1_000_000)]


class RiskAcceptanceCreate(StrictModel):
    justification: Justification
    compensating_control: Justification
    expires_on: date
    version: Annotated[int, Field(ge=1, le=1_000_000)]


class RevokeAcceptance(StrictModel):
    note: Annotated[str, Field(min_length=5, max_length=2000), AfterValidator(_text)]
    version: Annotated[int, Field(ge=1, le=1_000_000)]


# --- API: scans and SBOMs -------------------------------------------------------------------------


class ScanSummary(BaseModel):
    id: uuid.UUID
    reference: str
    application: AppRef
    source: ScanSource
    commit_sha: str | None
    branch: str | None
    imported_by_label: str
    imported_at: datetime
    generated_at: datetime
    reports: list[str]
    gate_passed: bool
    summary: dict[str, Any]


class ScanList(BaseModel):
    items: list[ScanSummary]


class SbomSummary(BaseModel):
    id: uuid.UUID
    application: AppRef
    scan: ScanRef
    artifact: str
    format: str
    spec_version: str
    subject: str
    subject_version: str | None
    component_count: int
    document_sha256: str
    created_at: datetime


class SbomList(BaseModel):
    items: list[SbomSummary]


class SbomComponent(BaseModel):
    name: str
    version: str | None
    type: str | None
    purl: str | None
    licenses: list[str]


class SbomDetail(SbomSummary):
    components: list[SbomComponent]
    components_total: int  # matching the filter, before the limit
