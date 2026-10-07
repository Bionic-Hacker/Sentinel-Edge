"""Tamper-evident audit log (ADR-0005).

Append-only by three independent mechanisms:
1. Grants: the app role has SELECT and INSERT only.
2. Triggers: UPDATE, DELETE and TRUNCATE raise, whoever runs them (until a table owner
   deliberately disables the trigger, which is itself DDL and visible).
3. Hash chain: each record commits to the previous one, so any edit, deletion or reordering of
   past records is detected by `python -m app.cli verify-audit`.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import BigInteger, CheckConstraint, DateTime, Identity, String, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models._types import StrEnumType


class AuditResult(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"


class AuditLog(Base):
    __tablename__ = "audit_log"
    __table_args__ = (
        CheckConstraint(
            "result IN (" + ", ".join(f"'{r.value}'" for r in AuditResult) + ")",
            name="result_valid",
        ),
        CheckConstraint("record_hash ~ '^[0-9a-f]{64}$'", name="record_hash_format"),
        CheckConstraint("prev_hash ~ '^[0-9a-f]{64}$'", name="prev_hash_format"),
    )

    seq: Mapped[int] = mapped_column(
        BigInteger, Identity(always=True), primary_key=True, autoincrement=True
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # No foreign key to users: audit records must outlive anything they describe.
    actor_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, index=True)
    actor_label: Mapped[str] = mapped_column(String(254), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    resource_type: Mapped[str | None] = mapped_column(String(64))
    resource_id: Mapped[str | None] = mapped_column(String(128))
    result: Mapped[AuditResult] = mapped_column(StrEnumType(AuditResult, 16), nullable=False)
    source_ip: Mapped[str | None] = mapped_column(String(45))
    correlation_id: Mapped[str | None] = mapped_column(String(64))
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    record_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
