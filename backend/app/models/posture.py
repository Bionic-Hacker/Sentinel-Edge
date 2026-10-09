"""Security posture snapshots (spec §40; ADR-0022).

The score itself is computed on demand from the control catalogue and live signals
(app.services.posture); a snapshot records it so the trend can be shown. Snapshots are
append-only for the application role (migration 0012).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class PostureSnapshot(Base):
    __tablename__ = "posture_snapshots"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    taken_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    overall: Mapped[int] = mapped_column(Integer, nullable=False)
    built_scope: Mapped[int] = mapped_column(Integer, nullable=False)
    categories: Mapped[dict[str, int]] = mapped_column(JSONB, nullable=False)
    taken_by_label: Mapped[str] = mapped_column(String(254), nullable=False)
