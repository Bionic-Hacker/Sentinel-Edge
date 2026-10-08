"""Protected application inventory API (spec §40)."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.orm import Session

from app.core.authz import Principal, any_role, require_roles
from app.core.request_context import request_context
from app.db.session import get_db
from app.models.user import Role
from app.schemas.applications import (
    ApplicationCreate,
    ApplicationList,
    ApplicationOut,
    ApplicationUpdate,
)
from app.schemas.incidents import AssigneeList
from app.services.applications import ApplicationService

router = APIRouter(prefix="/applications", tags=["applications"])
editors = require_roles(Role.ADMIN, Role.SECURITY_ENGINEER)


def get_service(request: Request, db: Session = Depends(get_db)) -> ApplicationService:  # noqa: B008
    return ApplicationService(db=db, ctx=request_context(request))


@router.get("", response_model=ApplicationList)
def list_applications(
    principal: Principal = Depends(any_role),  # noqa: B008  (developers: own applications only)
    service: ApplicationService = Depends(get_service),  # noqa: B008
) -> ApplicationList:
    return service.list_applications(principal)


@router.post("", response_model=ApplicationOut, status_code=status.HTTP_201_CREATED)
def create_application(
    body: ApplicationCreate,
    principal: Principal = Depends(editors),  # noqa: B008
    service: ApplicationService = Depends(get_service),  # noqa: B008
) -> ApplicationOut:
    return service.create(principal, body)


@router.get("/owners", response_model=AssigneeList)
def list_owners(
    _: Principal = Depends(editors),  # noqa: B008
    service: ApplicationService = Depends(get_service),  # noqa: B008
) -> AssigneeList:
    """People an application can be assigned to: active admins, security engineers and
    developers (names and roles only)."""
    return service.owners()


@router.get("/{application_id}", response_model=ApplicationOut)
def get_application(
    application_id: uuid.UUID,
    principal: Principal = Depends(any_role),  # noqa: B008  (object-level check in the service)
    service: ApplicationService = Depends(get_service),  # noqa: B008
) -> ApplicationOut:
    return service.get(principal, application_id)


@router.patch("/{application_id}", response_model=ApplicationOut)
def update_application(
    application_id: uuid.UUID,
    body: ApplicationUpdate,
    principal: Principal = Depends(editors),  # noqa: B008
    service: ApplicationService = Depends(get_service),  # noqa: B008
) -> ApplicationOut:
    return service.update(principal, application_id, body)
