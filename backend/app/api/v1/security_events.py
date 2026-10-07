"""Security events API (spec §12, §22). Read-only: events are evidence and cannot be edited."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.authz import Principal, require_roles
from app.core.errors import ApiError
from app.core.provenance import Provenance
from app.db.session import get_db
from app.models.security_event import (
    EventCategory,
    EventSource,
    SecurityEvent,
    Severity,
)
from app.models.user import Role
from app.schemas.security_events import EventDetail, EventPage, EventSummary

router = APIRouter(prefix="/security-events", tags=["security-operations"])
# Security operations data: investigators and read-only viewers; not developers (spec §28).
secops_readers = require_roles(Role.ADMIN, Role.SECURITY_ENGINEER, Role.ANALYST, Role.VIEWER)


@router.get("", response_model=EventPage)
def list_events(
    _: Principal = Depends(secops_readers),  # noqa: B008
    db: Session = Depends(get_db),  # noqa: B008
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    before_seq: Annotated[int | None, Query(ge=1)] = None,
    min_severity: Severity | None = None,
    category: EventCategory | None = None,
    source: EventSource | None = None,
    provenance: Provenance | None = None,
    source_ip: Annotated[str | None, Query(max_length=45, pattern=r"^[0-9a-fA-F:.]+$")] = None,
    since: datetime | None = None,
    until: datetime | None = None,
) -> EventPage:
    """Newest first, keyset-paginated by `seq`."""
    query = select(SecurityEvent).order_by(SecurityEvent.seq.desc()).limit(limit + 1)
    if before_seq is not None:
        query = query.where(SecurityEvent.seq < before_seq)
    if min_severity is not None:
        allowed = [s for s in Severity if s.rank >= min_severity.rank]
        query = query.where(SecurityEvent.severity.in_(allowed))
    if category is not None:
        query = query.where(SecurityEvent.category == category)
    if source is not None:
        query = query.where(SecurityEvent.source == source)
    if provenance is not None:
        query = query.where(SecurityEvent.provenance == provenance)
    if source_ip is not None:
        query = query.where(SecurityEvent.source_ip == source_ip)
    if since is not None:
        query = query.where(SecurityEvent.occurred_at >= since)
    if until is not None:
        query = query.where(SecurityEvent.occurred_at < until)

    rows = list(db.scalars(query).all())
    has_more = len(rows) > limit
    rows = rows[:limit]
    return EventPage(
        items=[EventSummary.model_validate(r, from_attributes=True) for r in rows],
        next_before_seq=rows[-1].seq if has_more and rows else None,
    )


@router.get("/{event_id}", response_model=EventDetail)
def get_event(
    event_id: uuid.UUID,
    _: Principal = Depends(secops_readers),  # noqa: B008
    db: Session = Depends(get_db),  # noqa: B008
) -> EventDetail:
    event = db.scalar(select(SecurityEvent).where(SecurityEvent.id == event_id))
    if event is None:
        raise ApiError(404, "not_found", "Not Found")
    return EventDetail.model_validate(event, from_attributes=True)
