"""The edge in AWS as SentinelEdge reads it back (ADR-0029)."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel

from app.models.security_event import Severity


class EnvironmentOut(BaseModel):
    environment: str
    deployed: bool
    region: str | None


class CertificateOut(BaseModel):
    arn: str
    region: str
    domain: str
    alternative_names: list[str]
    status: str
    type: str
    key_algorithm: str | None
    issuer: str | None
    not_before: datetime | None
    not_after: datetime | None
    days_left: int | None
    renewal_eligibility: str | None
    renewal_status: str | None
    in_use_by: int
    # Why it needs attention ("expiring", "expired", "renewal_failed", ...), or None.
    condition: str | None
    severity: Severity | None


class CertificateList(BaseModel):
    enabled: bool
    regions: list[str]
    items: list[CertificateOut]
    error: str | None = None


class SyncStatusOut(BaseModel):
    started_at: datetime | None
    finished_at: datetime | None
    waf_records_read: int
    waf_events_stored: int
    certificates_checked: int
    certificate_events_stored: int
    errors: list[str]


class RuleCount(BaseModel):
    rule: str
    count: int


class EdgeStatus(BaseModel):
    waf_logs_enabled: bool
    waf_log_group: str | None
    certificate_regions: list[str]
    sync_interval_seconds: int
    last_sync: SyncStatusOut | None
    waf_blocks_24h: int
    waf_blocks_by_rule: list[RuleCount]
