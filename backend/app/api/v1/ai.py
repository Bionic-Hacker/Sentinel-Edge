"""AI security engine API (Phase 9; ADR-0006, ADR-0007, ADR-0024).

Running an analysis spends tokens, so VIEWERs (including the read-only DAST scanner) cannot;
every role reads analyses and proposals it may see. Only leads decide proposals, and the AI
itself can never act: approving is what runs an action, as the person who approved it.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.ai.providers import Provider, ProviderError, get_provider
from app.core.authz import Principal, any_role, require_roles
from app.core.deps import app_settings
from app.core.errors import ApiError
from app.core.request_context import request_context
from app.db.session import get_db
from app.models.ai import ProposalStatus, SubjectType
from app.models.user import Role
from app.schemas.ai import (
    AiStatus,
    AnalysisDetail,
    AnalysisList,
    AnalysisRequest,
    ProposalDecision,
    ProposalList,
    ProposalOut,
)
from app.services.ai import AiService

router = APIRouter(prefix="/ai", tags=["ai"])
analysers = require_roles(Role.ADMIN, Role.SECURITY_ENGINEER, Role.ANALYST, Role.DEVELOPER)
leads = require_roles(Role.ADMIN, Role.SECURITY_ENGINEER)


def get_ai_provider(request: Request) -> Provider | None:
    """The configured provider (overridden in tests with deliberately hostile ones)."""
    try:
        return get_provider(app_settings(request))
    except ProviderError as exc:
        raise ApiError(503, "ai_unavailable", str(exc)) from None


def get_service(
    request: Request,
    db: Session = Depends(get_db),  # noqa: B008
    provider: Provider | None = Depends(get_ai_provider),  # noqa: B008
) -> AiService:
    return AiService(
        db=db, ctx=request_context(request), settings=app_settings(request), provider=provider
    )


@router.get("/status", response_model=AiStatus)
def ai_status(
    principal: Principal = Depends(any_role),  # noqa: B008
    service: AiService = Depends(get_service),  # noqa: B008
) -> AiStatus:
    return service.status(principal)


@router.post("/analyses", response_model=AnalysisDetail, status_code=201)
def run_analysis(
    body: AnalysisRequest,
    principal: Principal = Depends(analysers),  # noqa: B008  (subject visibility in the service)
    service: AiService = Depends(get_service),  # noqa: B008
) -> AnalysisDetail:
    return service.analyse(principal, body)


@router.get("/analyses", response_model=AnalysisList)
def list_analyses(
    principal: Principal = Depends(any_role),  # noqa: B008  (developers: own applications only)
    service: AiService = Depends(get_service),  # noqa: B008
    subject_type: SubjectType | None = None,
    subject_id: uuid.UUID | None = None,
) -> AnalysisList:
    return service.list_analyses(principal, subject_type, subject_id)


@router.get("/analyses/{analysis_id}", response_model=AnalysisDetail)
def get_analysis(
    analysis_id: uuid.UUID,
    principal: Principal = Depends(any_role),  # noqa: B008  (object-level check in the service)
    service: AiService = Depends(get_service),  # noqa: B008
) -> AnalysisDetail:
    return service.get_analysis(principal, analysis_id)


@router.get("/proposals", response_model=ProposalList)
def list_proposals(
    principal: Principal = Depends(any_role),  # noqa: B008  (developers: own applications only)
    service: AiService = Depends(get_service),  # noqa: B008
    status: ProposalStatus | None = None,
) -> ProposalList:
    return service.list_proposals(principal, status)


@router.post("/proposals/{proposal_id}/decision", response_model=ProposalOut)
def decide_proposal(
    proposal_id: uuid.UUID,
    body: ProposalDecision,
    principal: Principal = Depends(leads),  # noqa: B008
    service: AiService = Depends(get_service),  # noqa: B008
) -> ProposalOut:
    return service.decide(principal, proposal_id, body)
