"""Security exceptions and change management API (spec §38, §39; ADR-0023).

Whoever asks cannot approve (separation of duties). Nothing here deletes anything: requests are
withdrawn, rejected, expired, closed, cancelled or rolled back, and each record's history is
read from the hash-chained audit log.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.core.authz import Principal, any_role, require_roles
from app.core.request_context import request_context
from app.db.session import get_db
from app.models.risk_governance import ChangeStatus, ExceptionStatus
from app.models.user import Role
from app.schemas.risk_governance import (
    ChangeCreate,
    ChangeDetail,
    ChangeList,
    ChangeTransition,
    ExceptionClose,
    ExceptionCreate,
    ExceptionDecision,
    ExceptionDetail,
    ExceptionList,
)
from app.services.risk_governance import RiskGovernanceService

router = APIRouter(tags=["governance"])
# Developers raise requests for applications they own; leads raise and decide them.
requesters = require_roles(Role.ADMIN, Role.SECURITY_ENGINEER, Role.DEVELOPER)
leads = require_roles(Role.ADMIN, Role.SECURITY_ENGINEER)


def get_service(request: Request, db: Session = Depends(get_db)) -> RiskGovernanceService:  # noqa: B008
    return RiskGovernanceService(db=db, ctx=request_context(request))


@router.get("/exceptions", response_model=ExceptionList)
def list_exceptions(
    principal: Principal = Depends(any_role),  # noqa: B008  (developers: own applications only)
    service: RiskGovernanceService = Depends(get_service),  # noqa: B008
    status: ExceptionStatus | None = None,
) -> ExceptionList:
    return service.list_exceptions(principal, status)


@router.post("/exceptions", response_model=ExceptionDetail, status_code=201)
def request_exception(
    body: ExceptionCreate,
    principal: Principal = Depends(requesters),  # noqa: B008
    service: RiskGovernanceService = Depends(get_service),  # noqa: B008
) -> ExceptionDetail:
    return service.request_exception(principal, body)


@router.get("/exceptions/{exception_id}", response_model=ExceptionDetail)
def get_exception(
    exception_id: uuid.UUID,
    principal: Principal = Depends(any_role),  # noqa: B008  (object-level check in the service)
    service: RiskGovernanceService = Depends(get_service),  # noqa: B008
) -> ExceptionDetail:
    return service.get_exception(principal, exception_id)


@router.post("/exceptions/{exception_id}/decision", response_model=ExceptionDetail)
def decide_exception(
    exception_id: uuid.UUID,
    body: ExceptionDecision,
    principal: Principal = Depends(leads),  # noqa: B008
    service: RiskGovernanceService = Depends(get_service),  # noqa: B008
) -> ExceptionDetail:
    return service.decide_exception(principal, exception_id, body)


@router.post("/exceptions/{exception_id}/close", response_model=ExceptionDetail)
def close_exception(
    exception_id: uuid.UUID,
    body: ExceptionClose,
    principal: Principal = Depends(requesters),  # noqa: B008
    service: RiskGovernanceService = Depends(get_service),  # noqa: B008
) -> ExceptionDetail:
    return service.close_exception(principal, exception_id, body)


@router.get("/change-requests", response_model=ChangeList)
def list_changes(
    principal: Principal = Depends(any_role),  # noqa: B008  (developers: own applications only)
    service: RiskGovernanceService = Depends(get_service),  # noqa: B008
    status: ChangeStatus | None = None,
) -> ChangeList:
    return service.list_changes(principal, status)


@router.post("/change-requests", response_model=ChangeDetail, status_code=201)
def submit_change(
    body: ChangeCreate,
    principal: Principal = Depends(requesters),  # noqa: B008
    service: RiskGovernanceService = Depends(get_service),  # noqa: B008
) -> ChangeDetail:
    return service.submit_change(principal, body)


@router.get("/change-requests/{change_id}", response_model=ChangeDetail)
def get_change(
    change_id: uuid.UUID,
    principal: Principal = Depends(any_role),  # noqa: B008  (object-level check in the service)
    service: RiskGovernanceService = Depends(get_service),  # noqa: B008
) -> ChangeDetail:
    return service.get_change(principal, change_id)


@router.post("/change-requests/{change_id}/transition", response_model=ChangeDetail)
def transition_change(
    change_id: uuid.UUID,
    body: ChangeTransition,
    principal: Principal = Depends(requesters),  # noqa: B008
    service: RiskGovernanceService = Depends(get_service),  # noqa: B008
) -> ChangeDetail:
    return service.transition_change(principal, change_id, body)
