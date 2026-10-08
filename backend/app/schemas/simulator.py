"""Attack simulator models (spec §23). A run request names a scenario and nothing else: there
is no target, host or address to supply."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel

from app.models.security_event import EventCategory, Severity
from app.models.simulation import WafMode
from app.schemas.auth import StrictModel
from app.services.simulator import Scenario


class ScenarioOut(BaseModel):
    scenario: Scenario
    name: str
    description: str
    demonstrates: str


class ScenarioList(BaseModel):
    items: list[ScenarioOut]


class RunRequest(StrictModel):
    scenario: Scenario


class RunOut(BaseModel):
    id: uuid.UUID
    reference: str
    scenario: Scenario
    started_by_label: str
    started_at: datetime
    completed_at: datetime
    seed: int
    summary: dict[str, Any]


class RunList(BaseModel):
    items: list[RunOut]


class WafRuleOut(BaseModel):
    rule_id: str
    description: str
    category: EventCategory
    severity: Severity
    comparable_group: str
    mode: WafMode
    matches_24h: int
    updated_at: datetime | None
    updated_by_label: str | None


class WafRuleList(BaseModel):
    web_acl: str
    note: str
    items: list[WafRuleOut]


class WafModeRequest(StrictModel):
    mode: WafMode
