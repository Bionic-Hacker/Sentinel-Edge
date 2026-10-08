"""Protected application inventory (spec §40).

SentinelEdge is the first protected application (`is_platform`): its API count and live
telemetry come from this platform. Other applications can be registered with an owner,
criticality and domain; until their telemetry is connected the inventory says so instead of
inventing values. Applications are retired, never deleted (migration 0008).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Integer, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models._types import StrEnumType
from app.models.user import User


class AppEnvironment(StrEnum):
    LOCAL = "local"
    DEV = "dev"
    STAGING = "staging"
    PRODUCTION = "production"


class Criticality(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AppStatus(StrEnum):
    ACTIVE = "active"
    RETIRED = "retired"


def _check(column: str, enum: type[StrEnum]) -> CheckConstraint:
    values = ", ".join(f"'{v.value}'" for v in enum)
    return CheckConstraint(f"{column} IN ({values})", name=f"{column}_valid")


class Application(Base):
    __tablename__ = "applications"
    __table_args__ = (
        _check("environment", AppEnvironment),
        _check("criticality", Criticality),
        _check("status", AppStatus),
        CheckConstraint("slug ~ '^[a-z0-9][a-z0-9-]{0,62}$'", name="slug_format"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    slug: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    owner_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey(User.id, ondelete="SET NULL"), index=True
    )
    environment: Mapped[AppEnvironment] = mapped_column(
        StrEnumType(AppEnvironment, 16), nullable=False
    )
    criticality: Mapped[Criticality] = mapped_column(StrEnumType(Criticality, 16), nullable=False)
    # A hostname only. SentinelEdge never connects to it (no outbound requests, SSRF-safe).
    domain: Mapped[str | None] = mapped_column(String(253))
    status: Mapped[AppStatus] = mapped_column(StrEnumType(AppStatus, 16), nullable=False)
    is_platform: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
