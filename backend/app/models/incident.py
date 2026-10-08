"""Incidents and their timelines (spec §22).

An incident moves DETECTED -> TRIAGED -> INVESTIGATING -> CONTAINMENT -> REMEDIATION ->
VALIDATION -> CLOSED (the rules, including who may make each move, are in
app.services.incidents). Its evidence is the security events linked to it.

Integrity (migration 0007, test_database_roles.py):
* incidents can be created and updated by the application but never deleted: an incident is
  closed, not erased;
* the timeline is append-only: notes and state changes are evidence, so a correction is a new
  entry, never an edit;
* every timeline entry is committed to the hash-chained audit log by digest, so an altered entry
  is detectable (app.services.incidents.verify_timeline).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    Integer,
    String,
    Uuid,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.provenance import Provenance
from app.db.base import Base
from app.models._types import StrEnumType
from app.models.security_event import EventCategory, Severity
from app.models.user import User


class IncidentStatus(StrEnum):
    DETECTED = "DETECTED"
    TRIAGED = "TRIAGED"
    INVESTIGATING = "INVESTIGATING"
    CONTAINMENT = "CONTAINMENT"
    REMEDIATION = "REMEDIATION"
    VALIDATION = "VALIDATION"
    CLOSED = "CLOSED"


OPEN_STATUSES = tuple(s for s in IncidentStatus if s is not IncidentStatus.CLOSED)


class Resolution(StrEnum):
    RESOLVED = "resolved"  # remediated and validated
    ACCEPTED_RISK = "accepted_risk"  # validated, residual risk accepted by a lead
    FALSE_POSITIVE = "false_positive"  # not an attack
    DUPLICATE = "duplicate"  # tracked in another incident


class TimelineKind(StrEnum):
    CREATED = "created"
    STATUS_CHANGED = "status_changed"
    NOTE = "note"
    ASSIGNED = "assigned"
    UPDATED = "updated"
    SEVERITY_RAISED = "severity_raised"
    EVENTS_LINKED = "events_linked"


def _check(column: str, enum: type[StrEnum]) -> CheckConstraint:
    values = ", ".join(f"'{v.value}'" for v in enum)
    return CheckConstraint(f"{column} IN ({values})", name=f"{column}_valid")


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        _check("status", IncidentStatus),
        _check("severity", Severity),
        _check("category", EventCategory),
        _check("resolution", Resolution),
        _check("provenance", Provenance),
        CheckConstraint(
            "(status = 'CLOSED') = (resolution IS NOT NULL AND closed_at IS NOT NULL)",
            name="closed_has_resolution",
        ),
        Index("ix_incidents_dedupe_key_status", "dedupe_key", "status"),
        Index("ix_incidents_status_number", "status", "number"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    # Human reference (INC-0042). Sequential numbers are fine to show: access is by role, and
    # the API addresses incidents by UUID.
    number: Mapped[int] = mapped_column(Integer, Identity(always=True), unique=True, nullable=False)
    title: Mapped[str] = mapped_column(String(160), nullable=False)
    summary: Mapped[str] = mapped_column(String(2000), nullable=False, default="")
    severity: Mapped[Severity] = mapped_column(StrEnumType(Severity, 16), nullable=False)
    category: Mapped[EventCategory | None] = mapped_column(StrEnumType(EventCategory, 32))
    status: Mapped[IncidentStatus] = mapped_column(StrEnumType(IncidentStatus, 16), nullable=False)
    resolution: Mapped[Resolution | None] = mapped_column(StrEnumType(Resolution, 16))
    # Simulated incidents only ever hold simulated evidence, and real ones real evidence.
    provenance: Mapped[Provenance] = mapped_column(StrEnumType(Provenance, 16), nullable=False)
    source_ip: Mapped[str | None] = mapped_column(String(45))
    # The rule that opened the incident, and the event that triggered it (no foreign key: the
    # link from the event side is the authoritative one).
    detection_rule: Mapped[str | None] = mapped_column(String(32))
    trigger_event_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    # Groups automatic detections from one source while an incident is open:
    # "<provenance>|ip:<address>", "<provenance>|actor:<account>" or "<provenance>|category:<c>".
    dedupe_key: Mapped[str | None] = mapped_column(String(300))
    # Deleting a user unassigns their incidents; the timeline keeps who held them.
    owner_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey(User.id, ondelete="SET NULL"), index=True
    )
    created_by_label: Mapped[str] = mapped_column(String(254), nullable=False)
    remediation: Mapped[str | None] = mapped_column(String(4000))
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Optimistic concurrency: writers send the version they saw; a stale write is refused.
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    @property
    def reference(self) -> str:
        return f"INC-{self.number:04d}"


class IncidentTimelineEntry(Base):
    __tablename__ = "incident_timeline"
    __table_args__ = (
        _check("kind", TimelineKind),
        _check("from_status", IncidentStatus),
        _check("to_status", IncidentStatus),
    )

    seq: Mapped[int] = mapped_column(
        BigInteger, Identity(always=True), primary_key=True, autoincrement=True
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, nullable=False, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey(Incident.id), nullable=False, index=True
    )
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # Plain values, like the audit log: the record outlives the account.
    actor_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    actor_label: Mapped[str] = mapped_column(String(254), nullable=False)
    kind: Mapped[TimelineKind] = mapped_column(StrEnumType(TimelineKind, 24), nullable=False)
    from_status: Mapped[IncidentStatus | None] = mapped_column(StrEnumType(IncidentStatus, 16))
    to_status: Mapped[IncidentStatus | None] = mapped_column(StrEnumType(IncidentStatus, 16))
    # Analyst-written text: stored as given, rendered as text only.
    body: Mapped[str | None] = mapped_column(String(4000))
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
