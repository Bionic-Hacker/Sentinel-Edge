"""Response models for the API Security Center. Allow-listed fields only (OWASP API3)."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class EndpointMetrics(BaseModel):
    requests: int
    error_rate: float  # (4xx + 5xx) / requests, 0..1
    client_errors: int
    server_errors: int
    unauthenticated: int  # 401
    forbidden: int  # 403
    throttled: int  # 429
    security_rejections: int  # 401 + 403 + 429: the spec's "attack count"


class InventoryItem(BaseModel):
    method: str
    path: str
    summary: str
    authentication: str
    authorization: str
    roles: list[str]
    object_rule: str | None
    csrf_protected: bool
    risk: Literal["critical", "high", "medium", "low"]
    rate_limit: str
    owasp: list[str]
    data: str
    metrics: EndpointMetrics
    last_scan: datetime | None
    scan_note: str
    status: Literal["protected", "elevated", "review"]
    status_reasons: list[str]


class InventorySummary(BaseModel):
    endpoints: int
    public: int
    critical: int
    high: int
    requests: int
    security_rejections: int
    throttled: int
    unmatched_requests: int
    needs_attention: int


class InventoryResponse(BaseModel):
    generated_at: datetime
    window_hours: int
    metrics_enabled: bool
    summary: InventorySummary
    items: list[InventoryItem]


class OwaspCategory(BaseModel):
    code: str
    name: str
    status: Literal["mitigated", "partial", "not_exposed"]
    controls: list[str]
    evidence: list[str]
    planned: str | None
    exposed_endpoints: int


class OwaspResponse(BaseModel):
    edition: str
    items: list[OwaspCategory]
