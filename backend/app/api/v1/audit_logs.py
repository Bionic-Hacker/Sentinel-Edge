"""Audit log viewer API (spec §29). Read-only: there is no write, edit or delete endpoint."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.authz import Principal, require_roles
from app.core.request_context import request_context
from app.db.session import get_db
from app.models.audit import AuditLog, AuditResult
from app.models.user import Role
from app.schemas.audit import AuditEntryOut, AuditPage, ChainStatus
from app.services import audit
from app.services.audit import AuditAction, verify_chain

router = APIRouter(prefix="/audit-logs", tags=["audit"])
auditors = require_roles(Role.ADMIN, Role.SECURITY_ENGINEER)


@router.get("", response_model=AuditPage)
def list_audit_entries(
    _: Principal = Depends(auditors),  # noqa: B008
    db: Session = Depends(get_db),  # noqa: B008
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    before_seq: Annotated[int | None, Query(ge=1)] = None,
    action: Annotated[str | None, Query(max_length=64, pattern=r"^[a-z_.]+$")] = None,
    actor: Annotated[str | None, Query(max_length=254)] = None,
    result: AuditResult | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
) -> AuditPage:
    """Newest first, keyset-paginated by `seq` (stable under concurrent inserts, no OFFSET)."""
    query = select(AuditLog).order_by(AuditLog.seq.desc()).limit(limit + 1)
    if before_seq is not None:
        query = query.where(AuditLog.seq < before_seq)
    if action is not None:
        query = query.where(AuditLog.action == action)
    if actor is not None:
        query = query.where(AuditLog.actor_label == actor.strip().lower())
    if result is not None:
        query = query.where(AuditLog.result == result)
    if since is not None:
        query = query.where(AuditLog.occurred_at >= since)
    if until is not None:
        query = query.where(AuditLog.occurred_at < until)

    rows = list(db.scalars(query).all())
    has_more = len(rows) > limit
    rows = rows[:limit]
    return AuditPage(
        items=[AuditEntryOut.model_validate(r, from_attributes=True) for r in rows],
        next_before_seq=rows[-1].seq if has_more and rows else None,
    )


@router.get("/verify", response_model=ChainStatus)
def verify_audit_chain(
    request: Request,
    principal: Principal = Depends(auditors),  # noqa: B008
    db: Session = Depends(get_db),  # noqa: B008
) -> ChainStatus:
    status = verify_chain(db)
    audit.record(
        db,
        action=AuditAction.AUDIT_VERIFIED,
        result=AuditResult.SUCCESS if status.intact else AuditResult.FAILURE,
        actor=principal.user,
        ctx=request_context(request),
        details={"records_checked": status.records_checked, "intact": status.intact},
    )
    db.commit()
    return ChainStatus(
        intact=status.intact,
        records_checked=status.records_checked,
        head_hash=status.head_hash,
        first_break_seq=status.first_break_seq,
        problem=status.problem,
    )
