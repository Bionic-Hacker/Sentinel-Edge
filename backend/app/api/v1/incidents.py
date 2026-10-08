"""Incident management API (spec §22).

Reads: ADMIN, SECURITY_ENGINEER, ANALYST and VIEWER (read-only). Writes: ADMIN,
SECURITY_ENGINEER and ANALYST, with the object-level rules in app.services.incidents
(analysts work their own incidents; only leads close, reopen, re-rate or assign others).
"""

from __future__ import annotations

import uuid
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.orm import Session

from app.core.authz import Principal, require_roles
from app.core.request_context import request_context
from app.db.session import get_db
from app.models.incident import IncidentStatus
from app.models.security_event import Severity
from app.models.user import Role
from app.schemas.incidents import (
    AssigneeList,
    AssignmentRequest,
    IncidentCreate,
    IncidentDetail,
    IncidentPage,
    IncidentUpdate,
    LinkEventsRequest,
    NoteCreate,
    TransitionRequest,
)
from app.services.incidents import IncidentService

router = APIRouter(prefix="/incidents", tags=["security-operations"])
secops_readers = require_roles(Role.ADMIN, Role.SECURITY_ENGINEER, Role.ANALYST, Role.VIEWER)
investigators = require_roles(Role.ADMIN, Role.SECURITY_ENGINEER, Role.ANALYST)

State = Literal["open", "closed", "all"] | IncidentStatus


def get_service(request: Request, db: Session = Depends(get_db)) -> IncidentService:  # noqa: B008
    return IncidentService(db=db, ctx=request_context(request))


@router.get("", response_model=IncidentPage)
def list_incidents(
    principal: Principal = Depends(secops_readers),  # noqa: B008
    service: IncidentService = Depends(get_service),  # noqa: B008
    view: Literal["live", "simulated", "all"] = "all",
    state: State = "open",
    min_severity: Severity | None = None,
    owner: Literal["me", "unassigned"] | None = None,
    before_number: Annotated[int | None, Query(ge=1)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> IncidentPage:
    """Newest first, keyset-paginated by incident number."""
    return service.list_incidents(
        principal,
        view=view,
        state=str(state),
        min_severity=min_severity,
        owner=owner,
        before_number=before_number,
        limit=limit,
    )


@router.post("", response_model=IncidentDetail, status_code=status.HTTP_201_CREATED)
def create_incident(
    body: IncidentCreate,
    principal: Principal = Depends(investigators),  # noqa: B008
    service: IncidentService = Depends(get_service),  # noqa: B008
) -> IncidentDetail:
    return service.create(principal, body)


@router.get("/assignees", response_model=AssigneeList)
def list_assignees(
    _: Principal = Depends(investigators),  # noqa: B008
    service: IncidentService = Depends(get_service),  # noqa: B008
) -> AssigneeList:
    """People an incident can be assigned to: active admins, security engineers, analysts."""
    return service.assignees()


@router.get("/{incident_id}", response_model=IncidentDetail)
def get_incident(
    incident_id: uuid.UUID,
    principal: Principal = Depends(secops_readers),  # noqa: B008
    service: IncidentService = Depends(get_service),  # noqa: B008
) -> IncidentDetail:
    return service.detail(principal, incident_id)


@router.patch("/{incident_id}", response_model=IncidentDetail)
def update_incident(
    incident_id: uuid.UUID,
    body: IncidentUpdate,
    principal: Principal = Depends(investigators),  # noqa: B008  (object rules in the service)
    service: IncidentService = Depends(get_service),  # noqa: B008
) -> IncidentDetail:
    return service.update(principal, incident_id, body)


@router.post("/{incident_id}/transitions", response_model=IncidentDetail)
def transition_incident(
    incident_id: uuid.UUID,
    body: TransitionRequest,
    principal: Principal = Depends(investigators),  # noqa: B008  (object rules in the service)
    service: IncidentService = Depends(get_service),  # noqa: B008
) -> IncidentDetail:
    return service.transition(principal, incident_id, body)


@router.post("/{incident_id}/assignment", response_model=IncidentDetail)
def assign_incident(
    incident_id: uuid.UUID,
    body: AssignmentRequest,
    principal: Principal = Depends(investigators),  # noqa: B008  (object rules in the service)
    service: IncidentService = Depends(get_service),  # noqa: B008
) -> IncidentDetail:
    return service.assign(principal, incident_id, body)


@router.post(
    "/{incident_id}/notes", response_model=IncidentDetail, status_code=status.HTTP_201_CREATED
)
def add_note(
    incident_id: uuid.UUID,
    body: NoteCreate,
    principal: Principal = Depends(investigators),  # noqa: B008
    service: IncidentService = Depends(get_service),  # noqa: B008
) -> IncidentDetail:
    return service.add_note(principal, incident_id, body)


@router.post("/{incident_id}/events", response_model=IncidentDetail)
def link_events(
    incident_id: uuid.UUID,
    body: LinkEventsRequest,
    principal: Principal = Depends(investigators),  # noqa: B008  (object rules in the service)
    service: IncidentService = Depends(get_service),  # noqa: B008
) -> IncidentDetail:
    return service.link(principal, incident_id, body)
