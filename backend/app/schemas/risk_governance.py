"""Exception and change request API models (spec §38, §39; ADR-0023)."""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Annotated, Any

from pydantic import AfterValidator, BaseModel, Field, model_validator

from app.models.risk_governance import (
    ChangeStatus,
    ChangeType,
    ExceptionScope,
    ExceptionStatus,
    RiskLevel,
)
from app.models.simulation import WafMode
from app.schemas.applications import _line, _text
from app.schemas.auth import StrictModel

Version = Annotated[int, Field(ge=1, le=1_000_000)]
Title = Annotated[str, Field(min_length=5, max_length=200), AfterValidator(_line)]
Ref = Annotated[str, Field(min_length=1, max_length=200), AfterValidator(_line)]
Reason = Annotated[str, Field(min_length=20, max_length=4000), AfterValidator(_text)]
Text = Annotated[str, Field(max_length=4000), AfterValidator(_text)]
Note = Annotated[str, Field(min_length=10, max_length=2000), AfterValidator(_text)]
ControlRef = Annotated[str, Field(pattern=r"^C-[A-Z]+-[0-9]{2}$")]
Token = Annotated[str, Field(min_length=1, max_length=200, pattern=r"^[\x21-\x7e]+$")]


class AppRef(BaseModel):
    id: uuid.UUID
    slug: str
    name: str


class HistoryEntry(BaseModel):
    """One audit record about the item: its history is the hash-chained audit log itself."""

    seq: int
    occurred_at: datetime
    action: str
    actor_label: str
    note: str | None


# --- exceptions ------------------------------------------------------------------------------


class GateMatch(StrictModel):
    """How the scan gate recognises the finding: one fingerprint, or a tool and rule (with an
    optional fnmatch component pattern), exactly as scanning/accepted-findings.toml expects."""

    fingerprint: Annotated[str, Field(pattern=r"^[0-9a-f]{16,64}$")] | None = None
    tool: Annotated[str, Field(pattern=r"^[a-z]{2,16}$")] | None = None
    rule: Token | None = None
    component: Token | None = None

    @model_validator(mode="after")
    def _one_way(self) -> GateMatch:
        if self.fingerprint and (self.tool or self.rule or self.component):
            raise ValueError("match either a fingerprint or a tool and rule, not both")
        if not self.fingerprint and not (self.tool and self.rule):
            raise ValueError("a match needs a fingerprint, or a tool and a rule")
        return self


class ExceptionCreate(StrictModel):
    application_id: uuid.UUID | None = None  # defaults to SentinelEdge itself
    title: Title
    scope: ExceptionScope
    scope_ref: Ref
    gate_match: GateMatch | None = None
    risk_level: RiskLevel
    risk: Reason
    justification: Reason
    compensating_control: Reason
    control_refs: Annotated[list[ControlRef], Field(max_length=20)] = Field(default_factory=list)
    implementation: Text = ""
    exit_criteria: Text = ""
    expires_on: date

    @model_validator(mode="after")
    def _gate(self) -> ExceptionCreate:
        if (self.scope is ExceptionScope.SCAN_FINDING) != (self.gate_match is not None):
            raise ValueError("a gate match is required for, and only for, scan_finding")
        return self


class ExceptionDecision(StrictModel):
    approve: bool
    note: Text = ""
    version: Version


class ExceptionClose(StrictModel):
    note: Note
    version: Version


class ExceptionPermissions(BaseModel):
    can_decide: bool
    can_close: bool
    separation_of_duties: bool  # true when the caller could decide but is the requester


class ExceptionSummary(BaseModel):
    id: uuid.UUID
    reference: str
    title: str
    application: AppRef
    scope: ExceptionScope
    scope_ref: str
    risk_level: RiskLevel
    status: ExceptionStatus
    requester_label: str
    approver_label: str | None
    expires_on: date
    days_left: int | None  # while approved
    imported: bool
    version: int


class ExceptionDetail(ExceptionSummary):
    gate_match: dict[str, str] | None
    risk: str
    justification: str
    compensating_control: str
    control_refs: list[str]
    implementation: str
    exit_criteria: str
    decided_at: datetime | None
    decision_note: str | None
    ended_at: datetime | None
    end_note: str | None
    max_days: int
    created_at: datetime
    permissions: ExceptionPermissions
    history: list[HistoryEntry]


class ExceptionCounts(BaseModel):
    requested: int = 0
    approved: int = 0
    rejected: int = 0
    withdrawn: int = 0
    expired: int = 0
    closed: int = 0
    expiring_30d: int = 0


class ExceptionList(BaseModel):
    items: list[ExceptionSummary]
    counts: ExceptionCounts


# --- change requests ------------------------------------------------------------------------


class WafTarget(StrictModel):
    rule_id: Annotated[str, Field(pattern=r"^[A-Z]{2,8}-[0-9]{3}$")]
    mode: WafMode


class ChangeCreate(StrictModel):
    application_id: uuid.UUID | None = None  # defaults to SentinelEdge itself
    title: Title
    change_type: ChangeType
    description: Reason
    risk_level: RiskLevel
    impact: Reason
    rollback_plan: Reason
    validation_plan: Reason
    target: WafTarget | None = None

    @model_validator(mode="after")
    def _target(self) -> ChangeCreate:
        if (self.change_type is ChangeType.WAF_RULE) != (self.target is not None):
            raise ValueError("a WAF target is required for, and only for, waf_rule changes")
        return self


class ChangeTransition(StrictModel):
    to: ChangeStatus
    note: Text = ""
    implementation_ref: Token | None = None  # a pull request URL or commit, when implementing
    version: Version


class ChangeSummary(BaseModel):
    id: uuid.UUID
    reference: str
    title: str
    application: AppRef
    change_type: ChangeType
    risk_level: RiskLevel
    status: ChangeStatus
    requester_label: str
    approver_label: str | None
    created_at: datetime
    updated_at: datetime
    version: int


class ChangeDetail(ChangeSummary):
    description: str
    impact: str
    rollback_plan: str
    validation_plan: str
    target: dict[str, Any] | None
    previous_state: dict[str, Any] | None
    decided_at: datetime | None
    decision_note: str | None
    implemented_at: datetime | None
    implemented_by_label: str | None
    implementation_ref: str | None
    closed_at: datetime | None
    closing_note: str | None
    available_moves: list[ChangeStatus]
    separation_of_duties: bool  # true when the caller could approve but is the requester
    history: list[HistoryEntry]


class ChangeCounts(BaseModel):
    submitted: int = 0
    approved: int = 0
    rejected: int = 0
    cancelled: int = 0
    implemented: int = 0
    validated: int = 0
    rolled_back: int = 0


class ChangeList(BaseModel):
    items: list[ChangeSummary]
    counts: ChangeCounts
