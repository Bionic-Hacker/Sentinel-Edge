"""Column helpers shared by models."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Uuid
from sqlalchemy.orm import MappedColumn, mapped_column

from app.core.clock import utcnow


def uuid_pk() -> MappedColumn[uuid.UUID]:
    return mapped_column(Uuid, primary_key=True, default=uuid.uuid4)


def created_at() -> MappedColumn[datetime]:
    return mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


def timestamp(*, nullable: bool = True) -> MappedColumn[datetime]:
    return mapped_column(DateTime(timezone=True), nullable=nullable)
