"""Capability register endpoint (REAL vs SIMULATED transparency, spec §43).

Requires any authenticated role with account setup complete. (In Phase 1 it was public, tracked
as interim threat T-API-06; Phase 2 closed that exposure.)
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.core.authz import any_role
from app.core.capabilities import CAPABILITIES, Capability

router = APIRouter(prefix="/platform", tags=["platform"], dependencies=[Depends(any_role)])


class CapabilityList(BaseModel):
    items: list[Capability]


@router.get("/capabilities", response_model=CapabilityList)
def list_capabilities() -> CapabilityList:
    return CapabilityList(items=list(CAPABILITIES))
