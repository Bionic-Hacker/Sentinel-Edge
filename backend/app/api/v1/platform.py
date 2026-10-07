"""Capability register endpoint (REAL vs SIMULATED transparency, spec §43).

Phase 1 interim exposure: this endpoint is unauthenticated because authentication arrives in
Phase 2. It reveals only the public roadmap already in the README. Tracked as threat T-API-06
in docs/threat-model.md; Phase 2 moves it behind authentication (any authenticated role).
"""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from app.core.capabilities import CAPABILITIES, Capability

router = APIRouter(prefix="/platform", tags=["platform"])


class CapabilityList(BaseModel):
    items: list[Capability]


@router.get("/capabilities", response_model=CapabilityList)
def list_capabilities() -> CapabilityList:
    return CapabilityList(items=list(CAPABILITIES))
