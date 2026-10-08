"""Writing and verifying the tamper-evident audit log (ADR-0005, spec §29).

Each record's hash covers its own canonical content plus the previous record's hash:

    record_hash = SHA-256(prev_hash || "\\n" || canonical_json(record))

Changing, deleting or reordering any past record breaks every later link, and `verify_chain`
reports the first break. Writes take a transaction-scoped advisory lock so two concurrent requests
can never both extend the chain from the same previous record (which would fork it).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.clock import utcnow
from app.core.logging import redact
from app.models.audit import AuditLog, AuditResult
from app.models.user import User
from app.services import security_events

GENESIS_HASH = "0" * 64
# Arbitrary constant identifying "the audit chain" for pg_advisory_xact_lock.
_AUDIT_LOCK_KEY = 0x5E7E1ED6E
_MAX_DETAIL_STRING = 256


class AuditAction(StrEnum):
    LOGIN = "auth.login"
    LOGIN_MFA = "auth.login_mfa"
    LOGOUT = "auth.logout"
    ACCOUNT_LOCKED = "auth.account_locked"
    TOKEN_REFRESH = "auth.token_refresh"  # noqa: S105 - action name, not a secret  # nosec B105
    REFRESH_TOKEN_REUSE = "auth.refresh_token_reuse"  # noqa: S105 - action name, not a secret  # nosec B105
    MFA_ENROLLED = "auth.mfa_enrolled"
    PASSWORD_CHANGED = "auth.password_changed"  # noqa: S105 - action name, not a secret  # nosec B105
    PASSWORD_RESET_REQUESTED = "auth.password_reset_requested"  # noqa: S105 - action name, not a secret  # nosec B105
    PASSWORD_RESET = "auth.password_reset"  # noqa: S105 - action name, not a secret  # nosec B105
    USER_CREATED = "user.created"
    USER_UPDATED = "user.updated"
    USER_MFA_RESET = "user.mfa_reset"
    USER_DELETED = "user.deleted"
    AUDIT_VERIFIED = "audit.verified"
    ACCESS_DENIED = "authz.denied"
    RATE_LIMITED = "ratelimit.exceeded"
    INCIDENT_CREATED = "incident.created"
    INCIDENT_UPDATED = "incident.updated"
    INCIDENT_STATUS_CHANGED = "incident.status_changed"
    INCIDENT_ASSIGNED = "incident.assigned"
    INCIDENT_NOTE_ADDED = "incident.note_added"
    INCIDENT_EVENTS_LINKED = "incident.events_linked"
    SIMULATION_RUN = "simulator.run"
    SIMULATED_WAF_RULE_CHANGED = "simulator.waf_rule_changed"
    APPLICATION_CREATED = "application.created"
    APPLICATION_UPDATED = "application.updated"


@dataclass(frozen=True)
class RequestContext:
    source_ip: str | None = None
    user_agent: str | None = None
    correlation_id: str | None = None
    # Not part of the audit record itself; carried to the security event it may produce.
    method: str | None = None
    endpoint: str | None = None  # route template, e.g. "/api/v1/auth/login"


SYSTEM_CONTEXT = RequestContext()


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds")


def _clean_details(details: dict[str, Any] | None) -> dict[str, Any]:
    """Redact sensitive keys and bound string sizes: audit details are evidence, not a dump."""
    cleaned = redact(details or {})

    def bound(value: Any) -> Any:
        if isinstance(value, str):
            return value[:_MAX_DETAIL_STRING]
        if isinstance(value, dict):
            return {str(k): bound(v) for k, v in value.items()}
        if isinstance(value, list):
            return [bound(v) for v in value]
        if value is None or isinstance(value, bool | int):
            return value
        return str(value)[:_MAX_DETAIL_STRING]

    result: dict[str, Any] = bound(cleaned)
    return result


def canonical_payload(record: AuditLog) -> dict[str, Any]:
    """The exact content a record's hash commits to. Order-independent, type-stable."""
    return {
        "id": str(record.id),
        "occurred_at": _iso(record.occurred_at),
        "actor_id": str(record.actor_id) if record.actor_id else None,
        "actor_label": record.actor_label,
        "action": record.action,
        "resource_type": record.resource_type,
        "resource_id": record.resource_id,
        "result": str(record.result),
        "source_ip": record.source_ip,
        "correlation_id": record.correlation_id,
        "details": record.details,
    }


def compute_record_hash(prev_hash: str, payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(f"{prev_hash}\n{canonical}".encode()).hexdigest()


def record(
    db: Session,
    *,
    action: AuditAction,
    result: AuditResult,
    actor: User | str | None,
    ctx: RequestContext,
    resource_type: str | None = None,
    resource_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> AuditLog:
    """Append one audit record in the caller's transaction (commit together or not at all)."""
    db.execute(select(func.pg_advisory_xact_lock(_AUDIT_LOCK_KEY)))
    prev_hash = (
        db.scalar(select(AuditLog.record_hash).order_by(AuditLog.seq.desc()).limit(1))
        or GENESIS_HASH
    )
    if isinstance(actor, User):
        actor_id: uuid.UUID | None = actor.id
        actor_label = actor.email
    else:
        actor_id, actor_label = None, actor or "anonymous"

    entry = AuditLog(
        id=uuid.uuid4(),
        occurred_at=utcnow(),
        actor_id=actor_id,
        actor_label=actor_label,
        action=action.value,
        resource_type=resource_type,
        resource_id=resource_id,
        result=result,
        source_ip=ctx.source_ip,
        correlation_id=ctx.correlation_id,
        details=_clean_details(details),
        prev_hash=prev_hash,
    )
    entry.record_hash = compute_record_hash(prev_hash, canonical_payload(entry))
    db.add(entry)
    db.flush()
    # Security-relevant actions are also security events, in the same transaction.
    security_events.from_audit(
        db, entry, user_agent=ctx.user_agent, method=ctx.method, endpoint=ctx.endpoint
    )
    return entry


@dataclass(frozen=True)
class ChainVerification:
    records_checked: int
    head_hash: str
    first_break_seq: int | None
    problem: str | None

    @property
    def intact(self) -> bool:
        return self.first_break_seq is None


def _iter_records(db: Session, batch_size: int = 1000) -> Iterator[AuditLog]:
    last_seq = 0
    while True:
        batch = db.scalars(
            select(AuditLog).where(AuditLog.seq > last_seq).order_by(AuditLog.seq).limit(batch_size)
        ).all()
        if not batch:
            return
        yield from batch
        last_seq = batch[-1].seq


def verify_chain(db: Session) -> ChainVerification:
    """Walk the whole chain in order. Reports the first record whose link or content is wrong."""
    expected_prev = GENESIS_HASH
    count = 0
    for entry in _iter_records(db):
        count += 1
        if entry.prev_hash != expected_prev:
            return ChainVerification(count, expected_prev, entry.seq, "broken link to previous")
        if compute_record_hash(entry.prev_hash, canonical_payload(entry)) != entry.record_hash:
            return ChainVerification(count, expected_prev, entry.seq, "content does not match hash")
        expected_prev = entry.record_hash
    return ChainVerification(count, expected_prev, None, None)
