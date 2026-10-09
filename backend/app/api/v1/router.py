"""Version 1 API. Every route declares its authorization (tests/security/test_authz_matrix.py)."""

from fastapi import APIRouter

from app.api.v1 import (
    api_security,
    applications,
    audit_logs,
    auth,
    governance,
    health,
    incidents,
    platform,
    risk_governance,
    security_events,
    security_overview,
    simulator,
    users,
    vulnerabilities,
)

api_v1 = APIRouter(prefix="/api/v1")
api_v1.include_router(health.router)
api_v1.include_router(platform.router)
api_v1.include_router(auth.router)
api_v1.include_router(users.router)
api_v1.include_router(audit_logs.router)
api_v1.include_router(api_security.router)
api_v1.include_router(security_events.router)
api_v1.include_router(incidents.router)
api_v1.include_router(security_overview.router)
api_v1.include_router(applications.router)
api_v1.include_router(simulator.router)
api_v1.include_router(vulnerabilities.router)
api_v1.include_router(governance.router)
api_v1.include_router(risk_governance.router)
