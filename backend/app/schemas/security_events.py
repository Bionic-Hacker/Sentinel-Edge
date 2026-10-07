"""Security event response models."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel

from app.core.provenance import Provenance
from app.models.security_event import EventCategory, EventSource, Outcome, Severity


class EventSummary(BaseModel):
    id: uuid.UUID
    seq: int
    occurred_at: datetime
    provenance: Provenance
    source: EventSource
    category: EventCategory
    severity: Severity
    outcome: Outcome
    title: str
    rule_id: str | None
    source_ip: str | None
    method: str | None
    endpoint: str | None
    status_code: int | None
    actor_label: str | None


class EventDetail(EventSummary):
    user_agent: str | None
    correlation_id: str | None
    # Bounded, redacted data an attacker may have written. Clients must render it as text.
    evidence: dict[str, Any]


class EventPage(BaseModel):
    items: list[EventSummary]
    next_before_seq: int | None
