"""Vulnerability management API: findings, risk acceptances, scan runs and SBOMs (spec §19, §20).

Findings arrive only through `make scan-import` (the CLI, inside the API container); there is
no upload endpoint until CI can reach a deployed API (Phase 11). Nothing here deletes anything.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, Response
from sqlalchemy.orm import Session

from app.core.authz import Principal, any_role, require_roles
from app.core.request_context import request_context
from app.db.session import get_db
from app.models.security_event import Severity
from app.models.user import Role
from app.models.vulnerability import FindingCategory, ScanTool, VulnStatus
from app.schemas.vulnerabilities import (
    MAX_SBOM_COMPONENTS,
    RevokeAcceptance,
    RiskAcceptanceCreate,
    SbomDetail,
    SbomList,
    ScanList,
    ScanSummary,
    StatusChange,
    VulnerabilityDetail,
    VulnerabilityOverview,
    VulnerabilityPage,
)
from app.services.vulnerabilities import VulnerabilityService

router = APIRouter(tags=["vulnerability-management"])
# Developers fix their own applications' findings; leads also triage and accept risk.
remediators = require_roles(Role.ADMIN, Role.SECURITY_ENGINEER, Role.DEVELOPER)
leads = require_roles(Role.ADMIN, Role.SECURITY_ENGINEER)

Search = Annotated[str | None, Query(min_length=1, max_length=100)]


def get_service(request: Request, db: Session = Depends(get_db)) -> VulnerabilityService:  # noqa: B008
    return VulnerabilityService(db=db, ctx=request_context(request))


@router.get("/vulnerabilities", response_model=VulnerabilityPage)
def list_vulnerabilities(
    principal: Principal = Depends(any_role),  # noqa: B008  (developers: own applications only)
    service: VulnerabilityService = Depends(get_service),  # noqa: B008
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    before: Annotated[int | None, Query(ge=1)] = None,
    application_id: uuid.UUID | None = None,
    status: Annotated[list[VulnStatus] | None, Query(max_length=5)] = None,
    min_severity: Severity | None = None,
    category: FindingCategory | None = None,
    tool: ScanTool | None = None,
    fixable: bool | None = None,
    overdue: bool | None = None,
    q: Search = None,
) -> VulnerabilityPage:
    return service.list_vulnerabilities(
        principal,
        limit=limit,
        before=before,
        application_id=application_id,
        statuses=status or [],
        min_severity=min_severity,
        category=category,
        tool=tool,
        fixable=fixable,
        overdue=overdue,
        search=q,
    )


@router.get("/vulnerabilities/overview", response_model=VulnerabilityOverview)
def vulnerability_overview(
    principal: Principal = Depends(any_role),  # noqa: B008  (developers: own applications only)
    service: VulnerabilityService = Depends(get_service),  # noqa: B008
    application_id: uuid.UUID | None = None,
) -> VulnerabilityOverview:
    return service.overview(principal, application_id)


@router.get("/vulnerabilities/{vulnerability_id}", response_model=VulnerabilityDetail)
def get_vulnerability(
    vulnerability_id: uuid.UUID,
    principal: Principal = Depends(any_role),  # noqa: B008  (object-level check in the service)
    service: VulnerabilityService = Depends(get_service),  # noqa: B008
) -> VulnerabilityDetail:
    return service.get(principal, vulnerability_id)


@router.post("/vulnerabilities/{vulnerability_id}/status", response_model=VulnerabilityDetail)
def change_status(
    vulnerability_id: uuid.UUID,
    body: StatusChange,
    principal: Principal = Depends(remediators),  # noqa: B008
    service: VulnerabilityService = Depends(get_service),  # noqa: B008
) -> VulnerabilityDetail:
    return service.change_status(principal, vulnerability_id, body)


@router.post(
    "/vulnerabilities/{vulnerability_id}/acceptances",
    response_model=VulnerabilityDetail,
    status_code=201,
)
def accept_risk(
    vulnerability_id: uuid.UUID,
    body: RiskAcceptanceCreate,
    principal: Principal = Depends(leads),  # noqa: B008
    service: VulnerabilityService = Depends(get_service),  # noqa: B008
) -> VulnerabilityDetail:
    return service.accept_risk(principal, vulnerability_id, body)


@router.post(
    "/vulnerabilities/{vulnerability_id}/acceptances/{acceptance_id}/revoke",
    response_model=VulnerabilityDetail,
)
def revoke_acceptance(
    vulnerability_id: uuid.UUID,
    acceptance_id: uuid.UUID,
    body: RevokeAcceptance,
    principal: Principal = Depends(leads),  # noqa: B008
    service: VulnerabilityService = Depends(get_service),  # noqa: B008
) -> VulnerabilityDetail:
    return service.revoke_acceptance(principal, vulnerability_id, acceptance_id, body)


@router.get("/scans", response_model=ScanList)
def list_scans(
    principal: Principal = Depends(any_role),  # noqa: B008  (developers: own applications only)
    service: VulnerabilityService = Depends(get_service),  # noqa: B008
    application_id: uuid.UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
) -> ScanList:
    return service.list_scans(principal, application_id, limit)


@router.get("/scans/{scan_id}", response_model=ScanSummary)
def get_scan(
    scan_id: uuid.UUID,
    principal: Principal = Depends(any_role),  # noqa: B008  (object-level check in the service)
    service: VulnerabilityService = Depends(get_service),  # noqa: B008
) -> ScanSummary:
    return service.get_scan(principal, scan_id)


@router.get("/sboms", response_model=SbomList)
def list_sboms(
    principal: Principal = Depends(any_role),  # noqa: B008  (developers: own applications only)
    service: VulnerabilityService = Depends(get_service),  # noqa: B008
    application_id: uuid.UUID | None = None,
    latest: bool = True,
) -> SbomList:
    return service.list_sboms(principal, application_id, latest)


@router.get("/sboms/{sbom_id}", response_model=SbomDetail)
def get_sbom(
    sbom_id: uuid.UUID,
    principal: Principal = Depends(any_role),  # noqa: B008  (object-level check in the service)
    service: VulnerabilityService = Depends(get_service),  # noqa: B008
    q: Search = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0, le=MAX_SBOM_COMPONENTS)] = 0,
) -> SbomDetail:
    return service.get_sbom(principal, sbom_id, q, limit, offset)


@router.get("/sboms/{sbom_id}/document", response_class=Response, response_model=None)
def download_sbom(
    sbom_id: uuid.UUID,
    principal: Principal = Depends(any_role),  # noqa: B008  (object-level check in the service)
    service: VulnerabilityService = Depends(get_service),  # noqa: B008
) -> Response:
    """The CycloneDX document as imported, as a download (never rendered by the browser)."""
    sbom, body = service.sbom_document(principal, sbom_id)
    name = f"sbom-{sbom.application_id}-{sbom.artifact}.cdx.json"
    return Response(
        content=body,
        media_type="application/vnd.cyclonedx+json",
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )
