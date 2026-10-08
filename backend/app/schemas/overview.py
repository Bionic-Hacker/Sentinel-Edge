"""Security dashboard models (spec §12).

One view at a time: live (LOCAL and REAL_AWS) or simulated (SIMULATED and DEMO). The two are
never summed together. A control that does not exist yet reports `planned` with the phase that
delivers it, never a made-up value.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel

from app.models.incident import IncidentStatus
from app.models.security_event import EventCategory, Severity


class StatusLine(BaseModel):
    """Explainable overall status: the level and every reason for it."""

    level: Literal["ok", "attention", "critical"]
    reasons: list[str]


class IncidentStats(BaseModel):
    open: int
    unassigned: int
    by_severity: dict[str, int]
    by_status: dict[str, int]
    closed_in_window: int
    mean_minutes_to_triage: float | None
    mean_minutes_to_close: float | None


class RecentIncident(BaseModel):
    id: uuid.UUID
    reference: str
    title: str
    severity: Severity
    status: IncidentStatus
    detected_at: datetime


class EventStats(BaseModel):
    total: int
    detections: int
    stopped: int  # blocked at the edge, rejected by the application or throttled
    reached_app: int  # attack patterns in requests that were served or only counted
    by_category: dict[str, int]
    by_severity: dict[str, int]
    by_outcome: dict[str, int]


class SeriesPoint(BaseModel):
    hour: datetime
    events: int
    detections: int
    high_or_critical: int


class Source(BaseModel):
    source_ip: str
    events: int
    max_severity: Severity
    categories: list[EventCategory]
    country: str | None
    last_seen: datetime


class RuleCount(BaseModel):
    rule_id: str
    events: int


class CountryCount(BaseModel):
    country: str
    events: int


class TrafficPoint(BaseModel):
    hour: datetime
    requests: int
    rejected: int  # 401, 403, 429
    errors: int  # 5xx


class EndpointCount(BaseModel):
    method: str
    endpoint: str
    requests: int


class Traffic(BaseModel):
    """Live: all API requests, from the per-endpoint counters (no IPs are stored there).
    Simulated: the requests the simulator generated."""

    source: Literal["api_metrics", "simulator"]
    requests: int
    allowed: int
    rejected: int
    blocked_at_edge: int
    errors: int
    unknown_paths: int
    by_method: dict[str, int]
    series: list[TrafficPoint]
    top_endpoints: list[EndpointCount]


class Control(BaseModel):
    status: Literal["measured", "simulated", "planned"]
    summary: str
    values: dict[str, int]


class Overview(BaseModel):
    view: Literal["live", "simulated"]
    window_hours: int
    generated_at: datetime
    status: StatusLine
    incidents: IncidentStats
    recent_incidents: list[RecentIncident]
    events: EventStats
    series: list[SeriesPoint]
    top_sources: list[Source]
    top_rules: list[RuleCount]
    countries: list[CountryCount]
    traffic: Traffic
    controls: dict[str, Control]
