"""AI security engine API models (Phase 9; ADR-0007, ADR-0024)."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any

from pydantic import AfterValidator, BaseModel, Field

from app.ai.contract import AnalysisOutput
from app.core.provenance import Provenance
from app.models.ai import AnalysisStatus, ProposalStatus, ProposalType, SubjectType
from app.schemas.applications import _text
from app.schemas.auth import StrictModel

Version = Annotated[int, Field(ge=1, le=1_000_000)]
Note = Annotated[str, Field(min_length=10, max_length=2000), AfterValidator(_text)]


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class AnalysisRequest(StrictModel):
    subject_type: SubjectType
    subject_id: uuid.UUID


class Decision(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"


class ProposalDecision(StrictModel):
    version: Version
    decision: Decision
    # Required to reject, and to approve a proposal from a high prompt-risk analysis.
    note: Note | None = None


class SubjectRef(BaseModel):
    type: SubjectType
    id: uuid.UUID
    reference: str


class AppRef(BaseModel):
    id: uuid.UUID
    slug: str
    name: str


class ProposalOut(BaseModel):
    id: uuid.UUID
    reference: str
    analysis_id: uuid.UUID
    analysis_reference: str
    subject: SubjectRef
    action_type: ProposalType
    payload: dict[str, Any]
    rationale: str
    status: ProposalStatus
    # The prompt-risk score of the input behind the analysis that proposed it.
    input_risk: int
    note_required: bool
    can_decide: bool
    decided_by_label: str | None
    decided_at: datetime | None
    decision_note: str | None
    result_ref: str | None
    created_at: datetime
    version: int


class AnalysisSummary(BaseModel):
    id: uuid.UUID
    reference: str
    subject: SubjectRef
    application: AppRef | None
    provenance: Provenance
    status: AnalysisStatus
    provider: str
    model: str
    prompt_risk: int
    risk_level: RiskLevel
    classification: str | None
    severity: str | None
    proposals: int
    requested_by_label: str
    created_at: datetime


class AnalysisDetail(AnalysisSummary):
    failure: str | None
    risk_signals: list[str]
    input_sha256: str
    input_chars: int
    input_tokens: int
    output_tokens: int
    duration_ms: int
    output: AnalysisOutput | None
    # Where the AI disagrees with the platform's own verdict (shown, never acted on).
    disagreements: list[str]
    proposal_items: list[ProposalOut]


class AnalysisList(BaseModel):
    items: list[AnalysisSummary]


class ProposalCounts(BaseModel):
    proposed: int
    approved: int
    rejected: int


class ProposalList(BaseModel):
    items: list[ProposalOut]
    counts: ProposalCounts


class AiStatus(BaseModel):
    enabled: bool
    provider: str
    model: str | None
    provenance: Provenance | None
    can_analyse: bool
    requests_today: int
    requests_per_day: int
    tokens_today: int
    tokens_per_day: int
    max_output_tokens: int
