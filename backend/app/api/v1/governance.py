"""Threat modeling and control catalogue API (spec §36, §37; ADR-0022).

SentinelEdge's own threat model and the control catalogue are maintained as code and loaded
from the reviewed documents; here they are read-only. Leads create and edit threat models for
registered applications. Nothing here deletes anything: elements and threats are retired.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from app.core.authz import Principal, any_role, require_roles
from app.core.request_context import request_context
from app.db.session import get_db
from app.models.governance import ControlStatus
from app.models.user import Role
from app.schemas.governance import (
    ControlList,
    ElementCreate,
    ElementUpdate,
    RequirementList,
    ThreatCreate,
    ThreatModelCreate,
    ThreatModelDetail,
    ThreatModelList,
    ThreatModelUpdate,
    ThreatUpdate,
)
from app.services.governance import GovernanceService

router = APIRouter(tags=["governance"])
leads = require_roles(Role.ADMIN, Role.SECURITY_ENGINEER)

Family = Annotated[str | None, Query(pattern=r"^[A-Z]{2,8}$")]
Search = Annotated[str | None, Query(min_length=1, max_length=100)]


def get_service(request: Request, db: Session = Depends(get_db)) -> GovernanceService:  # noqa: B008
    return GovernanceService(db=db, ctx=request_context(request))


@router.get("/governance/controls", response_model=ControlList)
def list_controls(
    _: Principal = Depends(any_role),  # noqa: B008
    service: GovernanceService = Depends(get_service),  # noqa: B008
    status: ControlStatus | None = None,
    family: Family = None,
    q: Search = None,
) -> ControlList:
    return service.list_controls(status, family, q)


@router.get("/governance/requirements", response_model=RequirementList)
def list_requirements(
    _: Principal = Depends(any_role),  # noqa: B008
    service: GovernanceService = Depends(get_service),  # noqa: B008
) -> RequirementList:
    return service.list_requirements()


@router.get("/threat-models", response_model=ThreatModelList)
def list_threat_models(
    principal: Principal = Depends(any_role),  # noqa: B008  (developers: own applications only)
    service: GovernanceService = Depends(get_service),  # noqa: B008
    application_id: uuid.UUID | None = None,
) -> ThreatModelList:
    return service.list_models(principal, application_id)


@router.post("/threat-models", response_model=ThreatModelDetail, status_code=201)
def create_threat_model(
    body: ThreatModelCreate,
    principal: Principal = Depends(leads),  # noqa: B008
    service: GovernanceService = Depends(get_service),  # noqa: B008
) -> ThreatModelDetail:
    return service.create_model(principal, body)


@router.get("/threat-models/{model_id}", response_model=ThreatModelDetail)
def get_threat_model(
    model_id: uuid.UUID,
    principal: Principal = Depends(any_role),  # noqa: B008  (object-level check in the service)
    service: GovernanceService = Depends(get_service),  # noqa: B008
) -> ThreatModelDetail:
    return service.get_model(principal, model_id)


@router.patch("/threat-models/{model_id}", response_model=ThreatModelDetail)
def update_threat_model(
    model_id: uuid.UUID,
    body: ThreatModelUpdate,
    principal: Principal = Depends(leads),  # noqa: B008
    service: GovernanceService = Depends(get_service),  # noqa: B008
) -> ThreatModelDetail:
    return service.update_model(principal, model_id, body)


@router.post(
    "/threat-models/{model_id}/elements", response_model=ThreatModelDetail, status_code=201
)
def add_element(
    model_id: uuid.UUID,
    body: ElementCreate,
    principal: Principal = Depends(leads),  # noqa: B008
    service: GovernanceService = Depends(get_service),  # noqa: B008
) -> ThreatModelDetail:
    return service.add_element(principal, model_id, body)


@router.patch("/threat-models/{model_id}/elements/{element_id}", response_model=ThreatModelDetail)
def update_element(
    model_id: uuid.UUID,
    element_id: uuid.UUID,
    body: ElementUpdate,
    principal: Principal = Depends(leads),  # noqa: B008
    service: GovernanceService = Depends(get_service),  # noqa: B008
) -> ThreatModelDetail:
    return service.update_element(principal, model_id, element_id, body)


@router.post("/threat-models/{model_id}/threats", response_model=ThreatModelDetail, status_code=201)
def add_threat(
    model_id: uuid.UUID,
    body: ThreatCreate,
    principal: Principal = Depends(leads),  # noqa: B008
    service: GovernanceService = Depends(get_service),  # noqa: B008
) -> ThreatModelDetail:
    return service.add_threat(principal, model_id, body)


@router.patch("/threat-models/{model_id}/threats/{threat_id}", response_model=ThreatModelDetail)
def update_threat(
    model_id: uuid.UUID,
    threat_id: uuid.UUID,
    body: ThreatUpdate,
    principal: Principal = Depends(leads),  # noqa: B008
    service: GovernanceService = Depends(get_service),  # noqa: B008
) -> ThreatModelDetail:
    return service.update_threat(principal, model_id, threat_id, body)
