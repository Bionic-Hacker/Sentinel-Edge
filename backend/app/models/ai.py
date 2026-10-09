"""AI security analyses and the actions they propose (spec §21; ADR-0007, ADR-0024).

An **analysis** (AI-0001) records one call to the AI engine about one subject (a security event,
an incident, a finding or a threat model): who asked, which provider and model answered, what
the guardrails measured about the input (the prompt-risk score and its signals), what it cost in
tokens, and either the validated output or why the output was rejected. Analyses are evidence of
what the AI said: the application role may only INSERT them (migration 0014).

A **proposal** (AIP-0001) is the only thing the AI can produce besides text: a suggested action
from a short, fixed list (open an incident, raise a WAF change request, add a threat to a model).
Nothing happens until a lead approves it; the approval runs the action through the normal
service, as the approving person, in the same transaction as the decision. A decided proposal
is final: a trigger refuses any later change, for every role.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
    Uuid,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.provenance import Provenance
from app.db.base import Base
from app.models._types import StrEnumType
from app.models.application import Application


class SubjectType(StrEnum):
    SECURITY_EVENT = "security_event"
    INCIDENT = "incident"
    VULNERABILITY = "vulnerability"
    THREAT_MODEL = "threat_model"


class AnalysisStatus(StrEnum):
    COMPLETED = "completed"  # the output met the contract and was stored
    REJECTED = "rejected"  # the output broke the contract: stored as rejected, never repaired
    FAILED = "failed"  # the provider did not answer (error, timeout)


class ProposalType(StrEnum):
    OPEN_INCIDENT = "open_incident"  # from a security event not yet linked to an incident
    RAISE_CHANGE_REQUEST = "raise_change_request"  # a simulated WAF rule to BLOCK, never weaker
    ADD_THREAT = "add_threat"  # to an application threat model


class ProposalStatus(StrEnum):
    PROPOSED = "proposed"
    APPROVED = "approved"  # a lead approved it and the action ran
    REJECTED = "rejected"  # a lead rejected it


def _check(column: str, enum: type[StrEnum]) -> CheckConstraint:
    values = ", ".join(f"'{v.value}'" for v in enum)
    return CheckConstraint(f"{column} IN ({values})", name=f"{column}_valid")


class AiAnalysis(Base):
    __tablename__ = "ai_analyses"
    __table_args__ = (
        _check("subject_type", SubjectType),
        _check("status", AnalysisStatus),
        _check("provenance", Provenance),
        CheckConstraint("prompt_risk BETWEEN 0 AND 100", name="prompt_risk_range"),
        CheckConstraint(
            "(status = 'completed') = (output IS NOT NULL)", name="output_only_when_completed"
        ),
        Index("ix_ai_analyses_subject", "subject_type", "subject_id"),
        Index("ix_ai_analyses_requested", "requested_by_id", "created_at"),
        Index("ix_ai_analyses_created_at", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    number: Mapped[int] = mapped_column(Integer, Identity(always=True), unique=True, nullable=False)
    subject_type: Mapped[SubjectType] = mapped_column(StrEnumType(SubjectType, 16), nullable=False)
    subject_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    subject_ref: Mapped[str] = mapped_column(String(64), nullable=False)
    # The application the subject belongs to (developers see analyses of their own only).
    application_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey(Application.id))
    # Inherited from the subject: an analysis of simulated activity is SIMULATED.
    provenance: Mapped[Provenance] = mapped_column(StrEnumType(Provenance, 16), nullable=False)
    # No foreign key to users: like audit records, analyses outlive the accounts that asked.
    requested_by_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    requested_by_label: Mapped[str] = mapped_column(String(254), nullable=False)
    provider: Mapped[str] = mapped_column(String(16), nullable=False)
    model: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[AnalysisStatus] = mapped_column(StrEnumType(AnalysisStatus, 16), nullable=False)
    # Why the output was rejected or the call failed (our words, never the model's).
    failure: Mapped[str | None] = mapped_column(String(500))
    prompt_risk: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    risk_signals: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    # SHA-256 of the exact prompt sent, so a disputed answer can be tied to its input.
    input_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    input_chars: Mapped[int] = mapped_column(Integer, nullable=False)
    input_tokens: Mapped[int] = mapped_column(Integer, nullable=False)
    output_tokens: Mapped[int] = mapped_column(Integer, nullable=False)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    # The validated output (the contract in app.ai.contract), or null when not completed.
    output: Mapped[dict[str, Any] | None] = mapped_column(JSONB(none_as_null=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    @property
    def reference(self) -> str:
        return f"AI-{self.number:04d}"


class AiProposal(Base):
    __tablename__ = "ai_proposals"
    __table_args__ = (
        _check("action_type", ProposalType),
        _check("status", ProposalStatus),
        CheckConstraint(
            "(status = 'proposed') = (decided_at IS NULL)", name="decided_has_decision"
        ),
        CheckConstraint(
            "status <> 'approved' OR result_ref IS NOT NULL", name="approved_has_result"
        ),
        Index("ix_ai_proposals_status", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    number: Mapped[int] = mapped_column(Integer, Identity(always=True), unique=True, nullable=False)
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey(AiAnalysis.id), nullable=False, index=True
    )
    action_type: Mapped[ProposalType] = mapped_column(StrEnumType(ProposalType, 24), nullable=False)
    # The validated action (app.ai.contract), exactly as the AI proposed it.
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[ProposalStatus] = mapped_column(StrEnumType(ProposalStatus, 16), nullable=False)
    decided_by_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    decided_by_label: Mapped[str | None] = mapped_column(String(254))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    decision_note: Mapped[str | None] = mapped_column(String(2000))
    # What the approved action created (INC-0007, CHG-0003, TM-0002/TH-004).
    result_ref: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    @property
    def reference(self) -> str:
        return f"AIP-{self.number:04d}"
