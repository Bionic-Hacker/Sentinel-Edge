"""Application inventory models (spec §40).

Where a value is not available yet (no WAF, certificates or scanning until later phases), the
response says so and why, instead of showing a number that nothing measured.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, Field

from app.models.application import AppEnvironment, AppStatus, Criticality
from app.schemas.auth import StrictModel
from app.schemas.incidents import Person

# A DNS hostname (no scheme, port, path or credentials). SentinelEdge never connects to it.
_HOSTNAME = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*$")
_LINE_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_TEXT_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _hostname(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    if not _HOSTNAME.fullmatch(value):
        raise ValueError("must be a hostname such as app.example.com (no scheme, port or path)")
    return value


def _line(value: str) -> str:
    value = value.strip()
    if not value or _LINE_CONTROL.search(value):
        raise ValueError("must be a non-blank single line")
    return value


def _text(value: str) -> str:
    value = value.strip()
    if _TEXT_CONTROL.search(value):
        raise ValueError("must not contain control characters")
    return value


Name = Annotated[str, Field(min_length=1, max_length=100), AfterValidator(_line)]
Description = Annotated[str, Field(max_length=500), AfterValidator(_text)]
Domain = Annotated[str, Field(min_length=1, max_length=253), AfterValidator(_hostname)]
Slug = Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")]


class ApplicationCreate(StrictModel):
    slug: Slug
    name: Name
    description: Description = ""
    owner_id: uuid.UUID | None = None
    environment: AppEnvironment
    criticality: Criticality
    domain: Domain | None = None


class ApplicationUpdate(StrictModel):
    version: Annotated[int, Field(ge=1, le=1_000_000)]
    name: Name | None = None
    description: Description | None = None
    owner_id: uuid.UUID | None = None
    clear_owner: bool = False
    environment: AppEnvironment | None = None
    criticality: Criticality | None = None
    domain: Domain | None = None
    status: AppStatus | None = None


class Measure(BaseModel):
    """A value with its provenance: measured here, or not available yet and why."""

    status: Literal["measured", "not_connected", "planned"]
    value: int | None
    note: str


class ApplicationOut(BaseModel):
    id: uuid.UUID
    slug: str
    name: str
    description: str
    owner: Person | None
    environment: AppEnvironment
    criticality: Criticality
    domain: str | None
    status: AppStatus
    is_platform: bool
    version: int
    created_at: datetime
    updated_at: datetime
    api_count: Measure
    open_incidents: Measure
    security_events_24h: Measure
    waf_status: Measure
    certificate_status: Measure
    security_score: Measure
    last_scan: Measure
    vulnerability_count: Measure


class ApplicationList(BaseModel):
    items: list[ApplicationOut]
