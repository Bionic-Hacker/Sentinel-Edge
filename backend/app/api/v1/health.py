"""Liveness endpoint used by docker-compose now and by ALB/ECS health checks in Phase 4."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.core.config import Settings, get_settings

router = APIRouter(tags=["platform"])


class HealthResponse(BaseModel):
    status: Literal["ok"]
    version: str


@router.get("/health", response_model=HealthResponse)
def health(settings: Settings = Depends(get_settings)) -> HealthResponse:  # noqa: B008
    # Deliberately minimal: no hostnames, environment names, dependency versions, or
    # database details that would help an attacker fingerprint the deployment.
    return HealthResponse(status="ok", version=settings.app_version)
