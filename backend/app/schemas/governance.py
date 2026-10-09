"""Threat modeling and control catalogue API models (spec §36, §37; ADR-0022)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from pydantic import AfterValidator, BaseModel, Field, field_validator

from app.models.governance import (
    PASTA_STAGES,
    STRIDE_PATTERN,
    ControlStatus,
    ElementKind,
    ModelMethod,
    ModelOrigin,
    ModelStatus,
    ThreatStatus,
)
from app.schemas.applications import _line, _text
from app.schemas.auth import StrictModel

Version = Annotated[int, Field(ge=1, le=1_000_000)]
Line = Annotated[str, Field(min_length=1, max_length=200), AfterValidator(_line)]
LongLine = Annotated[str, Field(min_length=1, max_length=300), AfterValidator(_line)]
Text = Annotated[str, Field(max_length=4000), AfterValidator(_text)]
Stride = Annotated[str, Field(min_length=1, max_length=16, pattern=STRIDE_PATTERN)]
Score = Annotated[int, Field(ge=1, le=3)]
ControlRef = Annotated[str, Field(pattern=r"^C-[A-Z]+-[0-9]{2}$")]
BoundaryRef = Annotated[str, Field(pattern=r"^TB[0-9]{1,2}$")]
Owasp = Annotated[str, Field(max_length=64), AfterValidator(_text)]


# --- Controls and requirements ---------------------------------------------------------------


class Evidence(BaseModel):
    kind: str
    ref: str


class ControlExtension(BaseModel):
    phase: int
    title: str
    implementation: str
    evidence: list[Evidence]
    evidence_text: str


class ControlOut(BaseModel):
    ref: str
    title: str
    family: str
    layer: str | None
    status: ControlStatus
    phase: int
    implementation: str
    evidence: list[Evidence]
    evidence_text: str
    extensions: list[ControlExtension]
    threats: list[str]  # threat refs in the catalogue model that cite this control


class ControlCounts(BaseModel):
    implemented: int
    planned: int
    with_evidence: int


class ControlList(BaseModel):
    items: list[ControlOut]
    counts: ControlCounts
    catalogue_digest: str


class ThreatRef(BaseModel):
    ref: str
    title: str
    status: ThreatStatus
    risk: int


class RequirementOut(BaseModel):
    ref: str
    title: str
    threats: list[ThreatRef]
    controls: list[str]  # through its threats
    control_text: str
    implementation: str
    evidence: list[Evidence]
    evidence_text: str
    phase_text: str


class RequirementList(BaseModel):
    items: list[RequirementOut]


# --- Threat models ---------------------------------------------------------------------------


class AppRef(BaseModel):
    id: uuid.UUID
    slug: str
    name: str


class StatusCounts(BaseModel):
    open: int = 0
    planned: int = 0
    partly_mitigated: int = 0
    mitigated: int = 0
    accepted: int = 0
    not_exposed: int = 0
    closed: int = 0


class ThreatModelSummary(BaseModel):
    id: uuid.UUID
    reference: str
    name: str
    application: AppRef
    method: ModelMethod
    origin: ModelOrigin
    status: ModelStatus
    version_label: str
    threat_count: int
    by_status: StatusCounts
    # Highest L x I among threats still carrying risk (open, planned, partly mitigated); 0 if none.
    highest_open_risk: int
    updated_at: datetime
    version: int


class ThreatModelList(BaseModel):
    items: list[ThreatModelSummary]


class ElementOut(BaseModel):
    id: uuid.UUID
    kind: ElementKind
    ref: str
    name: str
    description: str
    boundaries: list[str]  # flows: the trust boundaries they cross
    threats: list[str]  # attack paths: the threats they chain
    retired: bool


class ThreatControlOut(BaseModel):
    ref: str
    title: str
    status: ControlStatus
    phase: int


class ThreatOut(BaseModel):
    id: uuid.UUID
    ref: str
    title: str
    stride: str
    owasp: str
    group: str
    boundaries: list[str]
    likelihood: int
    impact: int
    risk: int
    mitigation: str
    status: ThreatStatus
    status_text: str
    phases: list[int]
    controls: list[ThreatControlOut]
    retired: bool
    version: int


class RiskCell(BaseModel):
    likelihood: int
    impact: int
    count: int


class ModelStats(BaseModel):
    by_status: StatusCounts
    by_stride: dict[str, int]
    matrix: list[RiskCell]  # open threats (not mitigated, accepted or closed) per L x I cell
    unmapped: list[str]  # threats with no control at all
    only_planned_controls: list[str]  # threats whose every control is still planned


class ModelPermissions(BaseModel):
    can_edit: bool
    maintained_as_code: bool
    can_archive: bool  # leads, and developers on their own applications
    can_delete: bool  # leads only: permanent, audited


class ThreatModelDetail(BaseModel):
    id: uuid.UUID
    reference: str
    name: str
    application: AppRef
    method: ModelMethod
    origin: ModelOrigin
    status: ModelStatus
    scope: str
    version_label: str
    pasta: dict[str, str]
    elements: list[ElementOut]
    threats: list[ThreatOut]
    stats: ModelStats
    permissions: ModelPermissions
    created_by_label: str
    created_at: datetime
    updated_at: datetime
    version: int


def _pasta(value: dict[str, str] | None) -> dict[str, str] | None:
    if value is None:
        return None
    unknown = set(value) - set(PASTA_STAGES)
    if unknown:
        raise ValueError(f"unknown PASTA stages: {', '.join(sorted(unknown))}")
    for stage, text in value.items():
        if len(text) > 4000:
            raise ValueError(f"{stage}: at most 4000 characters")
        value[stage] = _text(text)
    return value


class ThreatModelCreate(StrictModel):
    application_id: uuid.UUID
    name: Line
    method: ModelMethod
    scope: Text = ""


class ThreatModelUpdate(StrictModel):
    version: Version
    name: Line | None = None
    scope: Text | None = None
    status: ModelStatus | None = None
    pasta: dict[str, str] | None = None

    _check_pasta = field_validator("pasta")(_pasta)


class ModelArchive(StrictModel):
    version: Version


class ElementCreate(StrictModel):
    kind: ElementKind
    name: LongLine
    description: Text = ""
    boundaries: Annotated[list[BoundaryRef], Field(max_length=10)] = Field(default_factory=list)


class ElementUpdate(StrictModel):
    name: LongLine | None = None
    description: Text | None = None
    retired: bool | None = None


class ThreatCreate(StrictModel):
    title: LongLine
    stride: Stride
    owasp: Owasp = ""
    boundaries: Annotated[list[BoundaryRef], Field(max_length=10)] = Field(default_factory=list)
    likelihood: Score
    impact: Score
    mitigation: Text = ""
    status: ThreatStatus = ThreatStatus.OPEN
    controls: Annotated[list[ControlRef], Field(max_length=20)] = Field(default_factory=list)


class ThreatUpdate(StrictModel):
    version: Version
    title: LongLine | None = None
    stride: Stride | None = None
    owasp: Owasp | None = None
    boundaries: Annotated[list[BoundaryRef], Field(max_length=10)] | None = None
    likelihood: Score | None = None
    impact: Score | None = None
    mitigation: Text | None = None
    status: ThreatStatus | None = None
    controls: Annotated[list[ControlRef], Field(max_length=20)] | None = None
    retired: bool | None = None
