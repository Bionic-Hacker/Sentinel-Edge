"""Correlation: detection rules over security events, and when an incident opens (Phase 7).

A single failed sign-in is noise; ten from one address across several accounts is credential
stuffing. Correlation rules turn streams of events into detections (events with source
`correlation`), and the incident policy decides which detections and events open, or join, an
incident.

Properties (tests/integration/test_correlation.py):
* Synchronous: correlation runs right after an event is stored, in the same transaction
  (app.services.security_events.record_event), so a detection exists exactly when its evidence
  does, and the API sees it on the next read.
* Provenance-partitioned: rules only ever count events of the triggering event's provenance.
  Simulated activity can raise only simulated detections and incidents (ADR-0009).
* Exactly once: correlation runs under the audit-chain advisory lock. Events fed from the audit
  log are recorded while that lock is held, and every incident change is audited, so taking it
  first everywhere gives one lock order (no deadlocks) and two concurrent requests can never
  raise the same detection twice.
* Bounded: a detection is raised at most once per rule, source and window, and lists at most
  CONTRIBUTING_LIMIT of the events behind it.
"""

from __future__ import annotations

import uuid
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any

from sqlalchemy import ColumnElement, and_, func, select
from sqlalchemy.orm import Session

from app.core.provenance import Provenance
from app.models.security_event import (
    EventCategory,
    EventSource,
    Outcome,
    SecurityEvent,
    Severity,
)

CONTRIBUTING_LIMIT = 50
# Must equal app.services.audit._AUDIT_LOCK_KEY (kept here to avoid an import cycle; a test
# asserts they are the same).
AUDIT_CHAIN_LOCK = 0x5E7E1ED6E

C = EventCategory
INJECTION = frozenset({C.SQL_INJECTION, C.XSS, C.PATH_TRAVERSAL, C.COMMAND_INJECTION, C.SSRF})


class GroupBy(StrEnum):
    SOURCE_IP = "source_ip"  # one attacking address
    ACTOR = "actor"  # one account (attacked, or acting)


@dataclass(frozen=True)
class CorrelationRule:
    rule_id: str
    name: str
    description: str
    categories: frozenset[EventCategory]
    group_by: GroupBy
    threshold: int  # events within the window
    window: timedelta
    severity: Severity
    # The detection's category; None means "the most frequent category among the matches".
    category: EventCategory | None = None
    # Minimum distinct accounts among the matches (0: no requirement; events from anonymous
    # requests have no account at all).
    min_distinct_actors: int = 0
    # Raise severity one level if any matching request got a success response.
    escalate_when_allowed: bool = False

    @property
    def window_minutes(self) -> int:
        return int(self.window.total_seconds() // 60)


RULES: tuple[CorrelationRule, ...] = (
    CorrelationRule(
        "COR-001",
        "Credential stuffing",
        "Failed sign-ins from one address against several accounts",
        frozenset({C.AUTH_FAILURE}),
        GroupBy.SOURCE_IP,
        threshold=10,
        window=timedelta(minutes=10),
        severity=Severity.HIGH,
        category=C.CREDENTIAL_STUFFING,
        min_distinct_actors=3,
    ),
    CorrelationRule(
        "COR-002",
        "Sustained password guessing",
        "Repeated failed sign-ins against one account, continuing past the lockout",
        frozenset({C.AUTH_FAILURE}),
        GroupBy.ACTOR,
        threshold=10,
        window=timedelta(minutes=15),
        severity=Severity.HIGH,
        category=C.BRUTE_FORCE,
    ),
    CorrelationRule(
        "COR-003",
        "Injection attack campaign",
        "Repeated injection payloads (SQL, script, path, command, SSRF) from one address",
        INJECTION,
        GroupBy.SOURCE_IP,
        threshold=5,
        window=timedelta(minutes=10),
        severity=Severity.HIGH,
        escalate_when_allowed=True,
    ),
    CorrelationRule(
        "COR-004",
        "Authorization probing",
        "One account repeatedly requesting objects or functions it may not use (BOLA/BFLA)",
        frozenset({C.BOLA, C.BFLA}),
        GroupBy.ACTOR,
        threshold=5,
        window=timedelta(minutes=10),
        severity=Severity.HIGH,
    ),
    CorrelationRule(
        "COR-005",
        "API abuse",
        "Repeated rate-limit violations from one address",
        frozenset({C.RATE_LIMIT}),
        GroupBy.SOURCE_IP,
        threshold=3,
        window=timedelta(minutes=10),
        severity=Severity.MEDIUM,
        category=C.API_ABUSE,
    ),
    CorrelationRule(
        "COR-006",
        "Automated scanning",
        "Scanner fingerprints or reconnaissance requests from one address",
        frozenset({C.SCANNER, C.RECON}),
        GroupBy.SOURCE_IP,
        threshold=3,
        window=timedelta(minutes=10),
        severity=Severity.MEDIUM,
        category=C.BOT,
    ),
)

# A successful sign-in from an address that has been failing against OTHER accounts is the
# moment credential stuffing works. Evaluated on sign-in, not on stored events, because
# successful sign-ins are routine and are not security events themselves.
SIGN_IN_AFTER_STUFFING = CorrelationRule(
    "COR-007",
    "Sign-in from a credential-stuffing source",
    "A sign-in succeeded from an address with recent failed sign-ins against other accounts",
    frozenset({C.AUTH_FAILURE}),
    GroupBy.SOURCE_IP,
    threshold=3,
    window=timedelta(minutes=15),
    severity=Severity.HIGH,
    category=C.SUSPICIOUS_AUTH,
)

ALL_RULES: tuple[CorrelationRule, ...] = (*RULES, SIGN_IN_AFTER_STUFFING)

# Single events that open an incident on their own, without correlation.
INCIDENT_CATEGORIES = frozenset({C.TOKEN_THEFT, C.SUSPICIOUS_AUTH, C.AUDIT_TAMPERING})


def lock(db: Session) -> None:
    """Serialize correlation with every audit write (see the module docstring)."""
    db.execute(select(func.pg_advisory_xact_lock(AUDIT_CHAIN_LOCK)))


def _key_column(rule: CorrelationRule) -> Any:
    return (
        SecurityEvent.source_ip if rule.group_by is GroupBy.SOURCE_IP else SecurityEvent.actor_label
    )


def _key(rule: CorrelationRule, event: SecurityEvent) -> str | None:
    return event.source_ip if rule.group_by is GroupBy.SOURCE_IP else event.actor_label


def _matching(
    rule: CorrelationRule, provenance: Provenance, key: str, since: datetime, until: datetime
) -> ColumnElement[bool]:
    return and_(
        SecurityEvent.provenance == provenance,
        SecurityEvent.source != EventSource.CORRELATION,
        SecurityEvent.category.in_(sorted(rule.categories)),
        _key_column(rule) == key,
        SecurityEvent.occurred_at >= since,
        SecurityEvent.occurred_at <= until,
    )


def _already_detected(
    db: Session, rule: CorrelationRule, provenance: Provenance, key: str, since: datetime
) -> bool:
    return (
        db.scalar(
            select(SecurityEvent.seq)
            .where(
                SecurityEvent.source == EventSource.CORRELATION,
                SecurityEvent.rule_id == rule.rule_id,
                SecurityEvent.provenance == provenance,
                _key_column(rule) == key,
                SecurityEvent.occurred_at >= since,
            )
            .limit(1)
        )
        is not None
    )


def _title(rule: CorrelationRule, key: str) -> str:
    where = f"from {key}" if rule.group_by is GroupBy.SOURCE_IP else f"against {key}"
    if rule.rule_id == "COR-004":
        where = f"by {key}"
    return f"{rule.name} {where}"


def _raise_detection(
    db: Session,
    rule: CorrelationRule,
    trigger: SecurityEvent,
    key: str,
    matches: list[SecurityEvent],
    *,
    total: int,
    distinct_actors: int,
) -> SecurityEvent:
    from app.services import security_events

    categories = Counter(m.category for m in matches)
    category = rule.category or categories.most_common(1)[0][0]
    severity = rule.severity
    allowed = any(m.outcome is Outcome.ALLOWED for m in matches)
    if rule.escalate_when_allowed and allowed:
        severity = severity.raised()
    ip_rule = rule.group_by is GroupBy.SOURCE_IP
    evidence: dict[str, Any] = {
        "rule": rule.rule_id,
        "name": rule.name,
        "description": rule.description,
        "window_minutes": rule.window_minutes,
        "threshold": rule.threshold,
        "events": total,
        "distinct_accounts": distinct_actors,
        "categories": {str(c): n for c, n in categories.most_common()},
        "first_seen": min(m.occurred_at for m in matches).isoformat(),
        "last_seen": max(m.occurred_at for m in matches).isoformat(),
        "any_allowed": allowed,
        "contributing_event_ids": [str(m.id) for m in matches],
    }
    return security_events.record_event(
        db,
        source=EventSource.CORRELATION,
        category=category,
        severity=severity,
        outcome=Outcome.ALLOWED if allowed else Outcome.DETECTED,
        title=_title(rule, key),
        rule_id=rule.rule_id,
        evidence=evidence,
        provenance=trigger.provenance,
        occurred_at=trigger.occurred_at,
        ctx=security_events.EventContext(
            source_ip=key if ip_rule else trigger.source_ip,
            actor_label=None if ip_rule else key,
            actor_id=None if ip_rule else trigger.actor_id,
            method=trigger.method,
            endpoint=trigger.endpoint,
            correlation_id=trigger.correlation_id,
            user_agent=trigger.user_agent,
        ),
        correlate=False,
    )


def evaluate(db: Session, rule: CorrelationRule, event: SecurityEvent) -> SecurityEvent | None:
    """Raise `rule`'s detection if `event` completes its pattern; None otherwise."""
    key = _key(rule, event)
    if key is None or event.category not in rule.categories:
        return None
    since = event.occurred_at - rule.window
    where = _matching(rule, event.provenance, key, since, event.occurred_at)
    total, distinct_actors = db.execute(
        select(func.count(), func.count(func.distinct(SecurityEvent.actor_label))).where(where)
    ).one()
    if total < rule.threshold or distinct_actors < rule.min_distinct_actors:
        return None
    if _already_detected(db, rule, event.provenance, key, since):
        return None
    matches = list(
        db.scalars(
            select(SecurityEvent)
            .where(where)
            .order_by(SecurityEvent.occurred_at.desc(), SecurityEvent.seq.desc())
            .limit(CONTRIBUTING_LIMIT)
        ).all()
    )
    return _raise_detection(
        db, rule, event, key, matches, total=total, distinct_actors=distinct_actors
    )


def opens_incident(event: SecurityEvent) -> bool:
    """The incident policy: which events (detections included) start or join an incident."""
    if event.source is EventSource.CORRELATION:
        return event.severity.rank >= Severity.HIGH.rank
    return event.severity is Severity.CRITICAL or event.category in INCIDENT_CATEGORIES


def on_event(db: Session, event: SecurityEvent) -> list[SecurityEvent]:
    """Correlate one newly stored event. Returns any detections raised."""
    from app.services import incidents

    lock(db)
    detections = [d for rule in RULES if (d := evaluate(db, rule, event)) is not None]
    for candidate in (event, *detections):
        if opens_incident(candidate):
            incidents.open_or_join(db, candidate)
    return detections


def on_sign_in(
    db: Session,
    *,
    provenance: Provenance,
    source_ip: str | None,
    account: str | None,
    actor_id: uuid.UUID | None,
    occurred_at: datetime,
    user_agent: str | None = None,
    endpoint: str | None = None,
    correlation_id: str | None = None,
) -> SecurityEvent | None:
    """COR-007: a successful sign-in from an address that has been failing against other
    accounts. Called when a session is established (after MFA, if the account has it)."""
    from app.services import incidents, security_events

    rule = SIGN_IN_AFTER_STUFFING
    if source_ip is None or account is None:
        return None
    lock(db)
    since = occurred_at - rule.window
    where = and_(
        _matching(rule, provenance, source_ip, since, occurred_at),
        SecurityEvent.actor_label != account,
    )
    total, distinct_others = db.execute(
        select(func.count(), func.count(func.distinct(SecurityEvent.actor_label))).where(where)
    ).one()
    if total < rule.threshold:
        return None
    already = db.scalar(
        select(SecurityEvent.seq)
        .where(
            SecurityEvent.source == EventSource.CORRELATION,
            SecurityEvent.rule_id == rule.rule_id,
            SecurityEvent.provenance == provenance,
            SecurityEvent.source_ip == source_ip,
            SecurityEvent.actor_label == account,
            SecurityEvent.occurred_at >= since,
        )
        .limit(1)
    )
    if already is not None:  # one detection per account and source per window
        return None
    matches = list(
        db.scalars(
            select(SecurityEvent)
            .where(where)
            .order_by(SecurityEvent.occurred_at.desc())
            .limit(CONTRIBUTING_LIMIT)
        ).all()
    )
    detection = security_events.record_event(
        db,
        source=EventSource.CORRELATION,
        category=EventCategory.SUSPICIOUS_AUTH,
        severity=rule.severity,
        outcome=Outcome.ALLOWED,
        title=f"Sign-in to {account} from a credential-stuffing source ({source_ip})",
        rule_id=rule.rule_id,
        provenance=provenance,
        occurred_at=occurred_at,
        evidence={
            "rule": rule.rule_id,
            "name": rule.name,
            "description": rule.description,
            "window_minutes": rule.window_minutes,
            "threshold": rule.threshold,
            "failed_sign_ins_against_other_accounts": total,
            "other_accounts": distinct_others,
            "contributing_event_ids": [str(m.id) for m in matches],
        },
        ctx=security_events.EventContext(
            source_ip=source_ip,
            actor_id=actor_id,
            actor_label=account,
            user_agent=user_agent,
            method="POST",
            endpoint=endpoint,
            correlation_id=correlation_id,
        ),
        correlate=False,
    )
    incidents.open_or_join(db, detection)
    return detection
