"""The edge in AWS, read back: real WAF blocks and ACM certificates (Phase 5, ADR-0029).

Read-only towards AWS. "Sync now" only pulls what the timer would pull anyway; rules and
certificates change only through Terraform.
"""

from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.authz import Principal, require_roles
from app.core.clock import utcnow
from app.core.config import Settings
from app.core.deps import app_settings
from app.core.errors import ApiError
from app.core.provenance import Provenance
from app.core.request_context import request_context
from app.db.session import get_db
from app.models.audit import AuditResult
from app.models.security_event import EventSource, SecurityEvent
from app.models.user import Role
from app.schemas.edge import (
    CertificateList,
    CertificateOut,
    EdgeStatus,
    RuleCount,
    SyncStatusOut,
)
from app.services import audit, aws_edge
from app.services.audit import AuditAction

router = APIRouter(prefix="/edge", tags=["edge"])
secops_readers = require_roles(Role.ADMIN, Role.SECURITY_ENGINEER, Role.ANALYST, Role.VIEWER)
operators = require_roles(Role.ADMIN, Role.SECURITY_ENGINEER)


def _sync_out(status: aws_edge.SyncStatus) -> SyncStatusOut | None:
    if status.started_at is None:
        return None
    return SyncStatusOut(**vars(status))


@router.get("/status", response_model=EdgeStatus)
def edge_status(
    _: Principal = Depends(secops_readers),  # noqa: B008
    db: Session = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(app_settings),  # noqa: B008
) -> EdgeStatus:
    since = utcnow() - timedelta(hours=24)
    rows = db.execute(
        select(SecurityEvent.rule_id, func.count())
        .where(
            SecurityEvent.source == EventSource.WAF,
            SecurityEvent.provenance == Provenance.REAL_AWS,
            SecurityEvent.occurred_at >= since,
        )
        .group_by(SecurityEvent.rule_id)
        .order_by(func.count().desc())
    ).all()
    return EdgeStatus(
        waf_logs_enabled=settings.waf_log_group is not None,
        waf_log_group=settings.waf_log_group,
        certificate_regions=settings.certificate_regions,
        sync_interval_seconds=settings.aws_sync_interval_seconds,
        last_sync=_sync_out(aws_edge.last_sync()),
        waf_blocks_24h=sum(n for _, n in rows),
        waf_blocks_by_rule=[RuleCount(rule=r or "unknown", count=n) for r, n in rows],
    )


@router.get("/certificates", response_model=CertificateList)
def list_certificates(
    _: Principal = Depends(secops_readers),  # noqa: B008
    settings: Settings = Depends(app_settings),  # noqa: B008
) -> CertificateList:
    if not settings.certificate_regions:
        return CertificateList(enabled=False, regions=[], items=[])
    try:
        found = aws_edge.certificates(settings)
    except Exception as exc:  # AWS unreachable or denied: say so, never AWS's own message
        return CertificateList(
            enabled=True,
            regions=settings.certificate_regions,
            items=[],
            error=f"Could not read ACM ({type(exc).__name__}).",
        )
    now = utcnow()
    items = []
    for cert in found:
        condition = cert.condition(now)
        items.append(
            CertificateOut(
                arn=cert.arn,
                region=cert.region,
                domain=cert.domain,
                alternative_names=cert.alternative_names,
                status=cert.status,
                type=cert.type,
                key_algorithm=cert.key_algorithm,
                issuer=cert.issuer,
                not_before=cert.not_before,
                not_after=cert.not_after,
                days_left=cert.days_left(now),
                renewal_eligibility=cert.renewal_eligibility,
                renewal_status=cert.renewal_status,
                in_use_by=cert.in_use_by,
                condition=condition[0] if condition else None,
                severity=condition[1] if condition else None,
            )
        )
    return CertificateList(enabled=True, regions=settings.certificate_regions, items=items)


@router.post("/sync", response_model=SyncStatusOut)
def sync_now(
    request: Request,
    principal: Principal = Depends(operators),  # noqa: B008
    db: Session = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(app_settings),  # noqa: B008
) -> SyncStatusOut:
    if not settings.aws_edge_enabled:
        raise ApiError(409, "edge_not_configured", "No AWS edge is configured here.")
    status = aws_edge.sync(request.app.state.session_factory, settings)
    audit.record(
        db,
        action=AuditAction.EDGE_SYNCED,
        result=AuditResult.FAILURE if status.errors else AuditResult.SUCCESS,
        actor=principal.user,
        ctx=request_context(request),
        resource_type="edge",
        details={
            "waf_events_stored": status.waf_events_stored,
            "certificate_events_stored": status.certificate_events_stored,
            "errors": status.errors,
        },
    )
    db.commit()
    return SyncStatusOut(**vars(status))
