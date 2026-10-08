"""Security dashboard API (spec §12): one view (live or simulated) at a time."""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from app.core.authz import Principal, require_roles
from app.db.session import get_db
from app.models.user import Role
from app.schemas.overview import Overview
from app.services.overview import OverviewService

router = APIRouter(prefix="/security", tags=["security-operations"])
secops_readers = require_roles(Role.ADMIN, Role.SECURITY_ENGINEER, Role.ANALYST, Role.VIEWER)


@router.get("/overview", response_model=Overview)
def security_overview(
    request: Request,
    _: Principal = Depends(secops_readers),  # noqa: B008
    db: Session = Depends(get_db),  # noqa: B008
    view: Literal["live", "simulated"] = "live",
    hours: Annotated[int, Query(ge=1, le=168)] = 24,
) -> Overview:
    return OverviewService(db=db, app=request.app).build(view=view, hours=hours)
