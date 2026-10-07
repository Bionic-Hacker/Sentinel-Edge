"""Token buckets for application rate limiting (ADR-0004, ADR-0017).

One row per (policy, subject), e.g. ``login|ip:203.0.113.7`` or ``read|user:<uuid>``. A bucket
holds up to `capacity` tokens and refills continuously; each request spends one. State lives in
PostgreSQL, so limits hold across every API task without a separate cache service.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models._types import timestamp


class RateLimitBucket(Base):
    __tablename__ = "rate_limit_buckets"

    bucket_key: Mapped[str] = mapped_column(String(200), primary_key=True)
    tokens: Mapped[float] = mapped_column(Float, nullable=False)
    # Indexed for pruning idle buckets.
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    # Outcome of the most recent request, and when the current run of denials began. Used to
    # audit the *first* denial of a run only, so a flood cannot flood the audit log too.
    last_allowed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    denied_since: Mapped[datetime | None] = timestamp()
