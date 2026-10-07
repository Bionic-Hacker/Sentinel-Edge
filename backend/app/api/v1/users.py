"""User management (spec §28). Admin-only except reading your own record."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.orm import Session

from app.core.authz import Principal, any_role, require_roles
from app.core.config import Settings
from app.core.deps import app_settings, password_hasher
from app.core.request_context import request_context
from app.db.session import get_db
from app.models.user import Role
from app.schemas.users import UserCreate, UserList, UserOut, UserUpdate
from app.security.passwords import PasswordHasher
from app.services.users import UserService

router = APIRouter(prefix="/users", tags=["users"])
admin_only = require_roles(Role.ADMIN)


def get_user_service(
    request: Request,
    db: Session = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(app_settings),  # noqa: B008
    hasher: PasswordHasher = Depends(password_hasher),  # noqa: B008
) -> UserService:
    return UserService(db=db, settings=settings, hasher=hasher, ctx=request_context(request))


@router.get("", response_model=UserList)
def list_users(
    _: Principal = Depends(admin_only),  # noqa: B008
    service: UserService = Depends(get_user_service),  # noqa: B008
) -> UserList:
    return UserList(items=service.list_users())


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    body: UserCreate,
    principal: Principal = Depends(admin_only),  # noqa: B008
    service: UserService = Depends(get_user_service),  # noqa: B008
) -> UserOut:
    return service.create_user(principal, body)


@router.get("/{user_id}", response_model=UserOut)
def get_user(
    user_id: uuid.UUID,
    principal: Principal = Depends(any_role),  # noqa: B008  (object-level check in the service)
    service: UserService = Depends(get_user_service),  # noqa: B008
) -> UserOut:
    return service.get_user(principal, user_id)


@router.patch("/{user_id}", response_model=UserOut)
def update_user(
    user_id: uuid.UUID,
    body: UserUpdate,
    principal: Principal = Depends(admin_only),  # noqa: B008
    service: UserService = Depends(get_user_service),  # noqa: B008
) -> UserOut:
    return service.update_user(principal, user_id, body)


@router.post("/{user_id}/mfa/reset", response_model=UserOut)
def reset_user_mfa(
    user_id: uuid.UUID,
    principal: Principal = Depends(admin_only),  # noqa: B008
    service: UserService = Depends(get_user_service),  # noqa: B008
) -> UserOut:
    return service.reset_mfa(principal, user_id)
