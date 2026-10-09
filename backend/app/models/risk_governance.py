"""Security exceptions and change management (spec §38, §39; ADR-0023).

An **exception** (EXC-0001) records a decision to live with a risk for a while: who asked, why,
how bad it is, what still protects the system, who approved it and until when. A **change
request** (CHG-0001) records a security-sensitive change before it is made: what, why, the risk,
how to roll it back and how to validate it, and who approved it.

Integrity (migration 0011, test_database_roles.py):
* separation of duties: the approver is never the requester, checked by the service and by a
  CHECK constraint, so not even a bug in the service can approve its own request;
* nothing is deleted by the application role; a decided record cannot be rewritten: a trigger
  refuses changes to the request and the decision once it is approved or rejected;
* history is the hash-chained audit log itself (resource_type `exception` / `change_request`),
  so a record's timeline cannot be edited without breaking the chain.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    Integer,
    String,
    Text,
    Uuid,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models._types import StrEnumType
from app.models.application import Application


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# The longest an exception may last, by its risk: a forced review, never a lapse.
MAX_EXCEPTION_DAYS: dict[RiskLevel, int] = {
    RiskLevel.CRITICAL: 30,
    RiskLevel.HIGH: 90,
    RiskLevel.MEDIUM: 180,
    RiskLevel.LOW: 365,
}


class ExceptionScope(StrEnum):
    DEPENDENCY = "dependency"  # a held-back or vulnerable package
    SCAN_FINDING = "scan_finding"  # exported to the scan gate's accepted-risk register
    CONTROL = "control"  # a catalogue control not (fully) applied
    CONFIGURATION = "configuration"
    OTHER = "other"


class ExceptionStatus(StrEnum):
    REQUESTED = "requested"
    APPROVED = "approved"
    REJECTED = "rejected"
    WITHDRAWN = "withdrawn"  # the requester took it back before a decision
    EXPIRED = "expired"  # the expiry passed: the risk is no longer accepted
    CLOSED = "closed"  # ended early: the underlying issue is fixed


class ChangeType(StrEnum):
    WAF_RULE = "waf_rule"  # drives the SIMULATED WAF; real WAF changes are Terraform PRs
    CONFIGURATION = "configuration"
    ACCESS = "access"
    DEPLOYMENT = "deployment"
    OTHER = "other"


class ChangeStatus(StrEnum):
    SUBMITTED = "submitted"
    APPROVED = "approved"
    REJECTED = "rejected"
    CANCELLED = "cancelled"
    IMPLEMENTED = "implemented"
    VALIDATED = "validated"
    ROLLED_BACK = "rolled_back"


def _check(column: str, enum: type[StrEnum]) -> CheckConstraint:
    values = ", ".join(f"'{v.value}'" for v in enum)
    return CheckConstraint(f"{column} IN ({values})", name=f"{column}_valid")


_SOD = CheckConstraint(
    "approver_id IS NULL OR requester_id IS NULL OR approver_id <> requester_id",
    name="approver_is_not_requester",
)


class SecurityException(Base):
    __tablename__ = "exceptions"
    __table_args__ = (
        _check("scope", ExceptionScope),
        _check("risk_level", RiskLevel),
        _check("status", ExceptionStatus),
        _SOD,
        CheckConstraint(
            "status IN ('requested', 'withdrawn') OR approver_label IS NOT NULL",
            name="decided_has_approver",
        ),
        CheckConstraint("(scope = 'scan_finding') = (gate_match IS NOT NULL)", name="gate_match"),
        Index("ix_exceptions_status", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    number: Mapped[int] = mapped_column(Integer, Identity(always=True), unique=True, nullable=False)
    application_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey(Application.id), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    scope: Mapped[ExceptionScope] = mapped_column(StrEnumType(ExceptionScope, 16), nullable=False)
    scope_ref: Mapped[str] = mapped_column(String(200), nullable=False)
    # scan_finding only: {"fingerprint"} or {"tool", "rule", "component"?} as the gate matches.
    gate_match: Mapped[dict[str, str] | None] = mapped_column(JSONB(none_as_null=True))
    risk_level: Mapped[RiskLevel] = mapped_column(StrEnumType(RiskLevel, 8), nullable=False)
    risk: Mapped[str] = mapped_column(Text, nullable=False)
    justification: Mapped[str] = mapped_column(Text, nullable=False)
    compensating_control: Mapped[str] = mapped_column(Text, nullable=False)
    control_refs: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    implementation: Mapped[str] = mapped_column(Text, nullable=False)
    exit_criteria: Mapped[str] = mapped_column(Text, nullable=False)
    expires_on: Mapped[date] = mapped_column(Date, nullable=False)
    status: Mapped[ExceptionStatus] = mapped_column(
        StrEnumType(ExceptionStatus, 12), nullable=False
    )
    # People are recorded by ID and label: a deleted account keeps its name in the record.
    requester_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    requester_label: Mapped[str] = mapped_column(String(254), nullable=False)
    approver_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    approver_label: Mapped[str | None] = mapped_column(String(254))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    decision_note: Mapped[str | None] = mapped_column(Text)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    end_note: Mapped[str | None] = mapped_column(Text)
    # Imported from docs/governance/exceptions.md, approved before separation of duties existed.
    imported: Mapped[bool] = mapped_column(Boolean, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)

    @property
    def reference(self) -> str:
        return f"EXC-{self.number:04d}"


class ChangeRequest(Base):
    __tablename__ = "change_requests"
    __table_args__ = (
        _check("change_type", ChangeType),
        _check("risk_level", RiskLevel),
        _check("status", ChangeStatus),
        _SOD,
        CheckConstraint(
            "status IN ('submitted', 'cancelled') OR approver_label IS NOT NULL",
            name="decided_has_approver",
        ),
        CheckConstraint("(change_type = 'waf_rule') = (target IS NOT NULL)", name="waf_target"),
        Index("ix_change_requests_status", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    number: Mapped[int] = mapped_column(Integer, Identity(always=True), unique=True, nullable=False)
    application_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey(Application.id), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    change_type: Mapped[ChangeType] = mapped_column(StrEnumType(ChangeType, 16), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    risk_level: Mapped[RiskLevel] = mapped_column(StrEnumType(RiskLevel, 8), nullable=False)
    impact: Mapped[str] = mapped_column(Text, nullable=False)
    rollback_plan: Mapped[str] = mapped_column(Text, nullable=False)
    validation_plan: Mapped[str] = mapped_column(Text, nullable=False)
    # waf_rule only: {"rule_id": "SQLI-001", "mode": "count"}.
    target: Mapped[dict[str, Any] | None] = mapped_column(JSONB(none_as_null=True))
    # waf_rule only: the mode in force when implemented, restored by a rollback.
    previous_state: Mapped[dict[str, Any] | None] = mapped_column(JSONB(none_as_null=True))
    status: Mapped[ChangeStatus] = mapped_column(StrEnumType(ChangeStatus, 12), nullable=False)
    requester_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    requester_label: Mapped[str] = mapped_column(String(254), nullable=False)
    approver_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    approver_label: Mapped[str | None] = mapped_column(String(254))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    decision_note: Mapped[str | None] = mapped_column(Text)
    implemented_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    implemented_by_label: Mapped[str | None] = mapped_column(String(254))
    implementation_ref: Mapped[str | None] = mapped_column(String(300))
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    closing_note: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)

    @property
    def reference(self) -> str:
        return f"CHG-{self.number:04d}"
