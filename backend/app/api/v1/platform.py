"""Capability register endpoint (REAL vs SIMULATED transparency, spec §43).

Requires any authenticated role with account setup complete. (In Phase 1 it was public, tracked
as interim threat T-API-06; Phase 2 closed that exposure.)
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.core.authz import any_role
from app.core.capabilities import CAPABILITIES, Capability
from app.core.config import Settings
from app.core.deps import app_settings
from app.schemas.edge import EnvironmentOut

router = APIRouter(prefix="/platform", tags=["platform"], dependencies=[Depends(any_role)])


class CapabilityList(BaseModel):
    items: list[Capability]


@router.get("/capabilities", response_model=CapabilityList)
def list_capabilities() -> CapabilityList:
    return CapabilityList(items=list(CAPABILITIES))


@router.get("/environment", response_model=EnvironmentOut)
def environment(settings: Settings = Depends(app_settings)) -> EnvironmentOut:  # noqa: B008
    """Where this API runs, for the page banner. Signed-in users only, unlike /health."""
    return EnvironmentOut(
        environment=settings.environment.value,
        deployed=settings.is_deployed,
        region=settings.aws_region if settings.is_deployed else None,
    )
