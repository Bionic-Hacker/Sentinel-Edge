"""Liveness and readiness probes.

- ``/health`` (liveness): the process is up. No dependencies, so a database outage never makes
  the orchestrator kill healthy containers in a restart loop. Used by Docker and ECS.
- ``/ready`` (readiness): the API can serve requests, i.e. the database answers as the app role.
  Used to decide whether to route traffic (ALB target health in Phase 4).

Both responses are deliberately minimal: no hostnames, environment names, dependency versions,
or error details that would help an attacker fingerprint the deployment.
"""

from __future__ import annotations

import logging
from typing import Literal

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.authz import public_endpoint
from app.core.config import Settings
from app.core.deps import app_settings
from app.core.errors import error_response
from app.db.session import get_db

# Probes are deliberately public: orchestrators and load balancers call them unauthenticated.
router = APIRouter(tags=["platform"], dependencies=[Depends(public_endpoint)])
logger = logging.getLogger("sentineledge.health")


class HealthResponse(BaseModel):
    status: Literal["ok"]
    version: str


class ReadyResponse(BaseModel):
    status: Literal["ready"]


@router.get("/health", response_model=HealthResponse)
def health(settings: Settings = Depends(app_settings)) -> HealthResponse:  # noqa: B008
    return HealthResponse(status="ok", version=settings.app_version)


@router.get(
    "/ready",
    response_model=ReadyResponse,
    responses={503: {"description": "Not ready"}},
)
def ready(db: Session = Depends(get_db)) -> ReadyResponse | JSONResponse:  # noqa: B008
    try:
        db.execute(text("SELECT 1"))
    except SQLAlchemyError as exc:
        # Full detail (host, error class) goes to internal logs only.
        logger.warning("readiness_check_failed", extra={"error_type": type(exc).__name__})
        return error_response(503, "not_ready", "Service not ready")
    return ReadyResponse(status="ready")
