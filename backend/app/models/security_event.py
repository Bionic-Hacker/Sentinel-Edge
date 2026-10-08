"""Security events: the telemetry that security operations works from (spec §12, §22-23).

Every row records ONE observation: a failed sign-in, an authorization denial, a rate-limit trip,
an attack pattern found in a request, or a correlated detection built from several of those.
Each carries its provenance (ADR-0009), so simulated activity can never pass as real.

Events are evidence. The application's database role may INSERT them and may UPDATE exactly
one column, `incident_id`, to link an event to an incident. A trigger makes that link
write-once, so evidence can be attached to an incident but never moved or detached; nothing
else about an event can be edited or deleted (migrations 0006-0007, test_database_roles.py).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    SmallInteger,
    String,
    Uuid,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.provenance import Provenance
from app.db.base import Base
from app.models._types import StrEnumType


class EventSource(StrEnum):
    """Which part of the platform observed the event."""

    AUTH = "auth"  # sign-in, MFA, session handling
    AUTHZ = "authz"  # function- and object-level authorization
    RATE_LIMIT = "rate_limit"  # application token buckets (ADR-0017)
    HTTP_ANALYSIS = "http_analysis"  # attack patterns in requests (detect-only)
    AUDIT = "audit"  # audit-chain integrity and privileged changes
    CORRELATION = "correlation"  # a detection rule over several events
    WAF = "waf"  # edge WAF: SIMULATED until AWS WAF exists (Phase 5)
    CERTIFICATE = "certificate"  # certificate monitoring: SIMULATED until Phase 5
    DEPENDENCY = "dependency"  # dependency scanning: SIMULATED until Phase 8


class EventCategory(StrEnum):
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    SSRF = "ssrf"
    SCANNER = "scanner"
    RECON = "recon"
    BOT = "bot"
    AUTH_FAILURE = "auth_failure"
    BRUTE_FORCE = "brute_force"
    CREDENTIAL_STUFFING = "credential_stuffing"
    TOKEN_THEFT = "token_theft"  # noqa: S105 - category name, not a secret  # nosec B105
    BOLA = "bola"
    BFLA = "bfla"
    PRIVILEGE_CHANGE = "privilege_change"
    RATE_LIMIT = "rate_limit"
    API_ABUSE = "api_abuse"
    AUDIT_TAMPERING = "audit_tampering"
    SUSPICIOUS_AUTH = "suspicious_auth"  # e.g. a sign-in from an address stuffing other accounts
    CERTIFICATE = "certificate"
    VULNERABLE_DEPENDENCY = "vulnerable_dependency"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)

    def raised(self, steps: int = 1) -> Severity:
        order = list(Severity)
        return order[min(len(order) - 1, self.rank + steps)]


class Outcome(StrEnum):
    """What happened to the request or action that produced the event."""

    ALLOWED = "allowed"  # it was served (a success response)
    REJECTED = "rejected"  # refused by validation, authentication or authorization
    THROTTLED = "throttled"  # refused by a rate limit
    BLOCKED = "blocked"  # stopped at the edge by a WAF (SIMULATED until Phase 5)
    DETECTED = "detected"  # an observation with no request of its own (e.g. a detection)


def _check(column: str, enum: type[StrEnum]) -> CheckConstraint:
    values = ", ".join(f"'{v.value}'" for v in enum)
    return CheckConstraint(f"{column} IN ({values})", name=f"{column}_valid")


class SecurityEvent(Base):
    __tablename__ = "security_events"
    __table_args__ = (
        _check("provenance", Provenance),
        _check("source", EventSource),
        _check("category", EventCategory),
        _check("severity", Severity),
        _check("outcome", Outcome),
        Index("ix_security_events_occurred_at", "occurred_at"),
        Index("ix_security_events_source_ip_occurred", "source_ip", "occurred_at"),
        Index("ix_security_events_category_occurred", "category", "occurred_at"),
        Index("ix_security_events_actor_occurred", "actor_label", "occurred_at"),
        Index("ix_security_events_rule_occurred", "rule_id", "occurred_at"),
    )

    # `seq` orders and paginates; `id` is the public, non-enumerable identifier.
    seq: Mapped[int] = mapped_column(
        BigInteger, Identity(always=True), primary_key=True, autoincrement=True
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, nullable=False, default=uuid.uuid4)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    provenance: Mapped[Provenance] = mapped_column(StrEnumType(Provenance, 16), nullable=False)
    source: Mapped[EventSource] = mapped_column(StrEnumType(EventSource, 24), nullable=False)
    category: Mapped[EventCategory] = mapped_column(StrEnumType(EventCategory, 32), nullable=False)
    severity: Mapped[Severity] = mapped_column(StrEnumType(Severity, 16), nullable=False)
    outcome: Mapped[Outcome] = mapped_column(StrEnumType(Outcome, 16), nullable=False)
    title: Mapped[str] = mapped_column(String(160), nullable=False)
    rule_id: Mapped[str | None] = mapped_column(String(32))
    source_ip: Mapped[str | None] = mapped_column(String(45))
    user_agent: Mapped[str | None] = mapped_column(String(256))
    method: Mapped[str | None] = mapped_column(String(10))
    # A route template when the request matched one; otherwise a sanitized, truncated path.
    endpoint: Mapped[str | None] = mapped_column(String(200))
    status_code: Mapped[int | None] = mapped_column(SmallInteger)
    # No foreign key to users: events, like audit records, outlive what they describe.
    actor_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    actor_label: Mapped[str | None] = mapped_column(String(254))
    correlation_id: Mapped[str | None] = mapped_column(String(64))
    # Bounded, redacted, control-character-free evidence. Rendered as text, never as markup.
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    # The incident this event is evidence for (write-once; see the module docstring).
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("incidents.id"), index=True
    )
