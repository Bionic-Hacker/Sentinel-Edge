"""Audit log query and response models."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel

from app.models.audit import AuditResult


class AuditEntryOut(BaseModel):
    seq: int
    id: uuid.UUID
    occurred_at: datetime
    actor_id: uuid.UUID | None
    actor_label: str
    action: str
    resource_type: str | None
    resource_id: str | None
    result: AuditResult
    source_ip: str | None
    correlation_id: str | None
    details: dict[str, Any]
    prev_hash: str
    record_hash: str


class AuditPage(BaseModel):
    items: list[AuditEntryOut]
    next_before_seq: int | None


class ChainStatus(BaseModel):
    intact: bool
    records_checked: int
    head_hash: str
    first_break_seq: int | None
    problem: str | None
