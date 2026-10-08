"""Attack simulator records (spec §23). Everything the simulator produces is SIMULATED.

* simulation_runs: who ran which scenario, when, and what it produced. Append-only.
* simulated_waf_rules: the mode (block, count or off) of each rule in the SIMULATED WAF. This
  is the only WAF rule state SentinelEdge's dashboard can change; real AWS WAF rules change only
  through Terraform (ADR-0008, Phase 5).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import CheckConstraint, DateTime, Identity, Integer, String, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models._types import StrEnumType


class WafMode(StrEnum):
    BLOCK = "block"
    COUNT = "count"
    OFF = "off"


class SimulationRun(Base):
    __tablename__ = "simulation_runs"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    number: Mapped[int] = mapped_column(Integer, Identity(always=True), unique=True, nullable=False)
    scenario: Mapped[str] = mapped_column(String(48), nullable=False)
    started_by_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    started_by_label: Mapped[str] = mapped_column(String(254), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    seed: Mapped[int] = mapped_column(Integer, nullable=False)
    # Requests, events, detections and incidents the run produced, plus the WAF modes it used.
    summary: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    @property
    def reference(self) -> str:
        return f"SIM-{self.number:04d}"


class SimulatedWafRule(Base):
    __tablename__ = "simulated_waf_rules"
    __table_args__ = (
        CheckConstraint(
            "mode IN (" + ", ".join(f"'{m.value}'" for m in WafMode) + ")", name="mode_valid"
        ),
    )

    rule_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    mode: Mapped[WafMode] = mapped_column(StrEnumType(WafMode, 8), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_by_label: Mapped[str] = mapped_column(String(254), nullable=False)
