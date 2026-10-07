"""API Security Center (spec §14): endpoint inventory and OWASP API Top 10 coverage."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.core.authz import Principal, require_roles
from app.models.user import Role
from app.schemas.api_security import InventoryResponse, OwaspResponse
from app.services.api_inventory import build_inventory, build_owasp

router = APIRouter(prefix="/api-security", tags=["api-security"])
# The inventory maps the attack surface: security staff and developers only.
api_security_readers = require_roles(Role.ADMIN, Role.SECURITY_ENGINEER, Role.DEVELOPER)


@router.get("/inventory", response_model=InventoryResponse)
def inventory(
    request: Request,
    _: Principal = Depends(api_security_readers),  # noqa: B008
) -> InventoryResponse:
    return build_inventory(request.app, request.app.state.api_metrics)


@router.get("/owasp", response_model=OwaspResponse)
def owasp(_: Principal = Depends(api_security_readers)) -> OwaspResponse:  # noqa: B008
    return build_owasp()
