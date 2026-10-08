"""Recording security events (spec §12, §22).

Two feeds write here:

* `from_audit`: security-relevant audit actions (failed sign-ins, lockouts, refresh-token
  reuse, authorization denials, rate-limit trips, privileged changes, a failed audit-chain
  check) also become events, in the same transaction as their audit record. Called from
  `app.services.audit.record`, so no feature can audit an attack without also reporting it.
* `record_http_analysis`: attack patterns found in a request by app.security.http_analysis.

Every event then passes through correlation (app.services.correlation), in the same
transaction, which can raise a detection and open or update an incident.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy.orm import Session

from app.core.clock import utcnow
from app.core.logging import redact
from app.core.provenance import Provenance
from app.models.security_event import EventCategory, EventSource, Outcome, SecurityEvent, Severity
from app.security.http_analysis import Analysis, event_severity

if TYPE_CHECKING:
    from app.models.audit import AuditLog

MAX_EVIDENCE_STRING = 256
MAX_EVIDENCE_ITEMS = 20
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_PRIVILEGED_ROLES = frozenset({"ADMIN", "SECURITY_ENGINEER"})


def bounded(value: Any, depth: int = 0) -> Any:
    """Evidence is data an attacker may have written: redact sensitive keys, strip control
    characters, and bound every string, list and nesting level."""
    if depth > 4:
        return "…"
    if isinstance(value, dict):
        items = list(value.items())[:MAX_EVIDENCE_ITEMS]
        return {_CONTROL.sub("?", str(k))[:64]: bounded(v, depth + 1) for k, v in items}
    if isinstance(value, list | tuple):
        return [bounded(v, depth + 1) for v in list(value)[:MAX_EVIDENCE_ITEMS]]
    if value is None or isinstance(value, bool | int | float):
        return value
    return _CONTROL.sub("?", str(value))[:MAX_EVIDENCE_STRING]


def _clip(value: str | None, size: int) -> str | None:
    return None if value is None else _CONTROL.sub("?", value)[:size]


@dataclass(frozen=True)
class EventContext:
    """Where an event came from: the request (or simulation) that produced it."""

    source_ip: str | None = None
    user_agent: str | None = None
    method: str | None = None
    endpoint: str | None = None
    status_code: int | None = None
    correlation_id: str | None = None
    actor_id: uuid.UUID | None = None
    actor_label: str | None = None


def record_event(
    db: Session,
    *,
    source: EventSource,
    category: EventCategory,
    severity: Severity,
    outcome: Outcome,
    title: str,
    ctx: EventContext,
    provenance: Provenance = Provenance.LOCAL,
    rule_id: str | None = None,
    evidence: dict[str, Any] | None = None,
    occurred_at: datetime | None = None,
    correlate: bool = True,
) -> SecurityEvent:
    """Add one event in the caller's transaction and correlate it (unless it is itself a
    detection, which correlation records with `correlate=False`)."""
    event = SecurityEvent(
        id=uuid.uuid4(),
        occurred_at=occurred_at or utcnow(),
        provenance=provenance,
        source=source,
        category=category,
        severity=severity,
        outcome=outcome,
        title=_clip(title, 160) or "",
        rule_id=_clip(rule_id, 32),
        source_ip=_clip(ctx.source_ip, 45),
        user_agent=_clip(ctx.user_agent, 256),
        method=_clip(ctx.method, 10),
        endpoint=_clip(ctx.endpoint, 200),
        status_code=ctx.status_code,
        actor_id=ctx.actor_id,
        actor_label=_clip(ctx.actor_label, 254),
        correlation_id=_clip(ctx.correlation_id, 64),
        evidence=bounded(redact(evidence or {})),
    )
    db.add(event)
    db.flush()
    if correlate:
        # Deferred import: correlation opens incidents, which audit, which feeds this module.
        from app.services import correlation

        correlation.on_event(db, event)
    return event


# --- Audit feed -------------------------------------------------------------------------------


_BOLA_TITLES = {
    "user": "Attempt to read another user's record",
    "incident": "Attempt to act on an incident assigned to someone else",
    "vulnerability": "Attempt to read another team's vulnerability",
    "scan": "Attempt to read another team's scan",
    "sbom": "Attempt to read another team's SBOM",
}


@dataclass(frozen=True)
class _Mapping:
    source: EventSource
    category: EventCategory
    severity: Severity
    outcome: Outcome
    title: str


def _map_audit(entry: AuditLog) -> _Mapping | None:
    """Which audit actions are security events, and how they read on the dashboard."""
    action, result, details = entry.action, str(entry.result), entry.details or {}
    failed = result in ("failure", "denied")
    if action == "auth.login" and failed:
        return _Mapping(
            EventSource.AUTH,
            EventCategory.AUTH_FAILURE,
            Severity.LOW,
            Outcome.REJECTED,
            "Failed sign-in",
        )
    if action == "auth.login_mfa" and failed:
        return _Mapping(
            EventSource.AUTH,
            EventCategory.AUTH_FAILURE,
            Severity.LOW,
            Outcome.REJECTED,
            "Failed second-factor verification",
        )
    if action == "auth.account_locked":
        return _Mapping(
            EventSource.AUTH,
            EventCategory.BRUTE_FORCE,
            Severity.MEDIUM,
            Outcome.REJECTED,
            "Account locked after repeated failures",
        )
    if action == "auth.refresh_token_reuse":
        return _Mapping(
            EventSource.AUTH,
            EventCategory.TOKEN_THEFT,
            Severity.HIGH,
            Outcome.REJECTED,
            "Rotated refresh token replayed: likely token theft",
        )
    if action == "authz.denied":
        if entry.resource_type == "endpoint":
            return _Mapping(
                EventSource.AUTHZ,
                EventCategory.BFLA,
                Severity.MEDIUM,
                Outcome.REJECTED,
                "Call to a function outside the caller's role",
            )
        return _Mapping(
            EventSource.AUTHZ,
            EventCategory.BOLA,
            Severity.MEDIUM,
            Outcome.REJECTED,
            _BOLA_TITLES.get(entry.resource_type or "", "Attempt to act on another user's object"),
        )
    if action == "ratelimit.exceeded":
        return _Mapping(
            EventSource.RATE_LIMIT,
            EventCategory.RATE_LIMIT,
            Severity.MEDIUM,
            Outcome.THROTTLED,
            f"Rate limit exceeded: {details.get('policy', 'unknown policy')}",
        )
    if action == "user.updated":
        granted = str((details.get("after") or {}).get("role", "")).split(".")[-1]
        if granted in _PRIVILEGED_ROLES:
            return _Mapping(
                EventSource.AUDIT,
                EventCategory.PRIVILEGE_CHANGE,
                Severity.MEDIUM,
                Outcome.ALLOWED,
                f"Privileged role granted: {granted}",
            )
        return None
    if action == "user.mfa_reset":
        return _Mapping(
            EventSource.AUDIT,
            EventCategory.PRIVILEGE_CHANGE,
            Severity.LOW,
            Outcome.ALLOWED,
            "Two-factor authentication reset by an administrator",
        )
    if action == "audit.verified" and failed:
        return _Mapping(
            EventSource.AUDIT,
            EventCategory.AUDIT_TAMPERING,
            Severity.CRITICAL,
            Outcome.DETECTED,
            "Audit log integrity check failed",
        )
    return None


def _establishes_session(entry: AuditLog) -> bool:
    """A successful sign-in that produced a session (after MFA, when the account has it)."""
    if str(entry.result) != "success":
        return False
    if entry.action == "auth.login_mfa":
        return True
    return entry.action == "auth.login" and (entry.details or {}).get("stage") == "complete"


def from_audit(
    db: Session,
    entry: AuditLog,
    *,
    user_agent: str | None,
    method: str | None,
    endpoint: str | None,
) -> SecurityEvent | None:
    if _establishes_session(entry):
        from app.services import correlation

        return correlation.on_sign_in(
            db,
            provenance=Provenance.LOCAL,
            source_ip=entry.source_ip,
            account=entry.actor_label,
            actor_id=entry.actor_id,
            occurred_at=entry.occurred_at,
            user_agent=user_agent,
            endpoint=endpoint,
            correlation_id=entry.correlation_id,
        )
    mapping = _map_audit(entry)
    if mapping is None:
        return None
    details = entry.details or {}
    evidence: dict[str, Any] = {"audit_action": entry.action, "audit_seq": entry.seq}
    for key in ("reason", "policy", "scope", "endpoint", "role", "required", "records_checked"):
        if key in details:
            evidence[key] = details[key]
    if entry.resource_type:
        evidence["resource"] = f"{entry.resource_type}:{entry.resource_id or ''}"
    return record_event(
        db,
        source=mapping.source,
        category=mapping.category,
        severity=mapping.severity,
        outcome=mapping.outcome,
        title=mapping.title,
        rule_id=None,
        evidence=evidence,
        ctx=EventContext(
            source_ip=entry.source_ip,
            user_agent=user_agent,
            method=method,
            endpoint=endpoint,
            correlation_id=entry.correlation_id,
            actor_id=entry.actor_id,
            actor_label=entry.actor_label,
        ),
    )


# --- HTTP analysis feed ------------------------------------------------------------------------


def outcome_for_status(status_code: int) -> Outcome:
    if status_code == 429:
        return Outcome.THROTTLED
    return Outcome.ALLOWED if status_code < 400 else Outcome.REJECTED


def record_http_analysis(
    db: Session,
    analysis: Analysis,
    ctx: EventContext,
    *,
    provenance: Provenance = Provenance.LOCAL,
    source: EventSource = EventSource.HTTP_ANALYSIS,
    outcome: Outcome | None = None,
    extra_evidence: dict[str, Any] | None = None,
    occurred_at: datetime | None = None,
) -> SecurityEvent:
    status = ctx.status_code or 0
    top = analysis.findings[0]
    lead = next(f for f in analysis.findings if f.category is analysis.category)
    evidence: dict[str, Any] = {
        "findings": [
            {
                "rule_id": f.rule_id,
                "category": str(f.category),
                "severity": str(f.severity),
                "description": f.description,
                "location": f.location,
                "field": f.field,
                "snippet": f.snippet,
            }
            for f in analysis.findings
        ],
        "mode": "detect-only",
        **(extra_evidence or {}),
    }
    count = len(analysis.findings)
    title = lead.description if count == 1 else f"{lead.description} (+{count - 1} more)"
    return record_event(
        db,
        source=source,
        category=analysis.category,
        severity=event_severity(analysis, status) if outcome is None else analysis.severity,
        outcome=outcome or outcome_for_status(status),
        title=title,
        rule_id=lead.rule_id or top.rule_id,
        evidence=evidence,
        ctx=ctx,
        provenance=provenance,
        occurred_at=occurred_at,
    )
