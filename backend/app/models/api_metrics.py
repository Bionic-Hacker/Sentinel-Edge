"""Per-endpoint request counters, aggregated by hour (API Security Center, spec §14).

Rows are counters, not request logs: no IPs, users, paths with IDs, or payloads are stored, so
the table carries no personal data and stays small whatever the traffic.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

UNMATCHED_ROUTE = "(unmatched)"  # requests that matched no API route (probing, typos, old URLs)


class ApiEndpointStat(Base):
    __tablename__ = "api_endpoint_stats"

    method: Mapped[str] = mapped_column(String(10), primary_key=True)
    route: Mapped[str] = mapped_column(String(200), primary_key=True)
    hour: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    requests: Mapped[int] = mapped_column(Integer, nullable=False)
    client_errors: Mapped[int] = mapped_column(Integer, nullable=False)  # 4xx
    server_errors: Mapped[int] = mapped_column(Integer, nullable=False)  # 5xx
    unauthenticated: Mapped[int] = mapped_column(Integer, nullable=False)  # 401
    forbidden: Mapped[int] = mapped_column(Integer, nullable=False)  # 403
    throttled: Mapped[int] = mapped_column(Integer, nullable=False)  # 429
