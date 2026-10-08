"""Incident request and response models (spec §22).

Requests reject unknown fields (mass assignment) and bound every string. Free text is stored as
written and rendered as text only; control characters other than line breaks and tabs are
refused, so text cannot forge log lines or hide content in the UI.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Annotated, Any

from pydantic import AfterValidator, BaseModel, Field

from app.core.provenance import Provenance
from app.models.incident import IncidentStatus, Resolution, TimelineKind
from app.models.security_event import EventCategory, Severity
from app.models.user import Role
from app.schemas.auth import StrictModel
from app.schemas.security_events import EventDetail, EventSummary

_LINE_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_TEXT_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _single_line(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("must not be blank")
    if _LINE_CONTROL.search(value):
        raise ValueError("must be a single line without control characters")
    return value


def _text(value: str) -> str:
    value = value.strip()
    if _TEXT_CONTROL.search(value):
        raise ValueError("must not contain control characters")
    return value


def _required_text(value: str) -> str:
    value = _text(value)
    if not value:
        raise ValueError("must not be blank")
    return value


Title = Annotated[str, Field(min_length=1, max_length=160), AfterValidator(_single_line)]
Summary = Annotated[str, Field(max_length=2000), AfterValidator(_text)]
Remediation = Annotated[str, Field(max_length=4000), AfterValidator(_text)]
NoteText = Annotated[str, Field(min_length=1, max_length=4000), AfterValidator(_required_text)]
ShortNote = Annotated[str, Field(min_length=1, max_length=2000), AfterValidator(_required_text)]
Version = Annotated[int, Field(ge=1, le=1_000_000)]
EventIds = Annotated[list[uuid.UUID], Field(max_length=50)]


# --- Requests ---------------------------------------------------------------------------------


class IncidentCreate(StrictModel):
    title: Title
    summary: Summary = ""
    severity: Severity
    category: EventCategory | None = None
    # Evidence to attach now. All must share one provenance, which the incident inherits.
    event_ids: EventIds = Field(default_factory=list)


class IncidentUpdate(StrictModel):
    version: Version
    title: Title | None = None
    summary: Summary | None = None
    remediation: Remediation | None = None
    severity: Severity | None = None


class TransitionRequest(StrictModel):
    version: Version
    to_status: IncidentStatus
    resolution: Resolution | None = None
    note: ShortNote | None = None


class AssignmentRequest(StrictModel):
    version: Version
    owner_id: uuid.UUID | None


class NoteCreate(StrictModel):
    body: NoteText


class LinkEventsRequest(StrictModel):
    version: Version
    event_ids: Annotated[list[uuid.UUID], Field(min_length=1, max_length=50)]


# --- Responses --------------------------------------------------------------------------------


class Person(BaseModel):
    id: uuid.UUID
    display_name: str
    role: Role


class IncidentSummary(BaseModel):
    id: uuid.UUID
    reference: str
    title: str
    severity: Severity
    category: EventCategory | None
    status: IncidentStatus
    resolution: Resolution | None
    provenance: Provenance
    source_ip: str | None
    detection_rule: str | None
    owner: Person | None
    event_count: int
    detected_at: datetime
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None


class IncidentPage(BaseModel):
    items: list[IncidentSummary]
    next_before_number: int | None


class TimelineEntry(BaseModel):
    id: uuid.UUID
    at: datetime
    actor_label: str
    kind: TimelineKind
    from_status: IncidentStatus | None
    to_status: IncidentStatus | None
    # Analyst-written text. Clients must render it as text.
    body: str | None
    details: dict[str, Any]


class AvailableMove(BaseModel):
    to_status: IncidentStatus
    label: str
    resolutions: list[Resolution]
    note_required: bool


class Permissions(BaseModel):
    """What the caller may do now. The server enforces all of it; clients use it to render."""

    can_edit: bool
    can_change_severity: bool
    can_assign: bool
    can_take: bool
    can_add_note: bool
    can_link_events: bool
    moves: list[AvailableMove]


class RiskFactor(BaseModel):
    reason: str
    points: int


class RiskScore(BaseModel):
    """Explainable: the score is the sum of the listed factors, capped at 100."""

    score: int
    factors: list[RiskFactor]


class Integrity(BaseModel):
    """Every timeline entry checked against the digest committed in the audit hash chain."""

    verified: bool
    entries_checked: int
    first_mismatch: uuid.UUID | None


class IncidentDetail(IncidentSummary):
    summary: str
    remediation: str | None
    version: int
    created_by_label: str
    trigger_event: EventDetail | None
    events: list[EventSummary]
    timeline: list[TimelineEntry]
    risk: RiskScore
    integrity: Integrity
    permissions: Permissions


class AssigneeList(BaseModel):
    items: list[Person]
