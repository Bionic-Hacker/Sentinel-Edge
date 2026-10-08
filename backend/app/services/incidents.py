"""Incident management (spec §22): the workflow, who may do what, and evidence integrity.

Workflow: DETECTED -> TRIAGED -> INVESTIGATING -> CONTAINMENT -> REMEDIATION -> VALIDATION ->
CLOSED, one step at a time, plus three deliberate exceptions:
* VALIDATION -> REMEDIATION when validation fails (a note says why);
* any open status -> CLOSED as a false positive or duplicate (a note says why);
* CLOSED -> INVESTIGATING to reopen (a note says why).
Closing as resolved or accepted risk is possible only from VALIDATION, with remediation
recorded.

Who may do what (enforced here; the UI only mirrors it):
* Leads (ADMIN, SECURITY_ENGINEER) may act on any incident, and only they may close, reopen,
  change severity or assign incidents to others.
* ANALYSTs work the incidents assigned to them. They may take an unassigned incident, and
  triaging an unassigned DETECTED incident takes it. Acting on someone else's incident is
  refused (403) and audited as an authorization denial.
* VIEWERs read only (enforced by the route guards).
* Anyone who may write may add a note to any incident, open or closed.

Integrity: every change is a timeline entry, and every timeline entry is committed to the
hash-chained audit log by SHA-256 digest (`verify_timeline`). Events are linked as evidence
write-once, never moved or detached, and only within one provenance: a simulated incident can
never hold real evidence or the reverse. Concurrent edits are refused by version check (409).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.core.api_policy import ENDPOINTS, Risk
from app.core.authz import Principal
from app.core.clock import utcnow
from app.core.errors import ApiError
from app.core.provenance import Provenance
from app.models.audit import AuditLog, AuditResult
from app.models.incident import (
    OPEN_STATUSES,
    Incident,
    IncidentStatus,
    IncidentTimelineEntry,
    Resolution,
    TimelineKind,
)
from app.models.security_event import EventSource, Outcome, SecurityEvent, Severity
from app.models.user import Role, User
from app.schemas.incidents import (
    AssigneeList,
    AssignmentRequest,
    AvailableMove,
    IncidentCreate,
    IncidentDetail,
    IncidentPage,
    IncidentSummary,
    IncidentUpdate,
    Integrity,
    LinkEventsRequest,
    NoteCreate,
    Permissions,
    Person,
    RiskFactor,
    RiskScore,
    TimelineEntry,
    TransitionRequest,
)
from app.schemas.security_events import EventDetail, EventSummary
from app.services import audit
from app.services.audit import AuditAction, RequestContext
from app.services.security_events import bounded

SYSTEM_ACTOR = "system:detection-engine"
LEADS = frozenset({Role.ADMIN, Role.SECURITY_ENGINEER})
INVESTIGATORS = frozenset({Role.ADMIN, Role.SECURITY_ENGINEER, Role.ANALYST})
LIVE = (Provenance.LOCAL, Provenance.REAL_AWS)
SIMULATED = (Provenance.SIMULATED, Provenance.DEMO)
MAX_TIMELINE = 500
MAX_EVENTS = 200

S = IncidentStatus
FORWARD: dict[IncidentStatus, IncidentStatus] = {
    S.DETECTED: S.TRIAGED,
    S.TRIAGED: S.INVESTIGATING,
    S.INVESTIGATING: S.CONTAINMENT,
    S.CONTAINMENT: S.REMEDIATION,
    S.REMEDIATION: S.VALIDATION,
    S.VALIDATION: S.CLOSED,
}
EARLY_CLOSE = (Resolution.FALSE_POSITIVE, Resolution.DUPLICATE)
VALIDATED_CLOSE = (Resolution.RESOLVED, Resolution.ACCEPTED_RISK)

AUDIT_ACTION: dict[TimelineKind, AuditAction] = {
    TimelineKind.CREATED: AuditAction.INCIDENT_CREATED,
    TimelineKind.STATUS_CHANGED: AuditAction.INCIDENT_STATUS_CHANGED,
    TimelineKind.NOTE: AuditAction.INCIDENT_NOTE_ADDED,
    TimelineKind.ASSIGNED: AuditAction.INCIDENT_ASSIGNED,
    TimelineKind.UPDATED: AuditAction.INCIDENT_UPDATED,
    TimelineKind.SEVERITY_RAISED: AuditAction.INCIDENT_UPDATED,
    TimelineKind.EVENTS_LINKED: AuditAction.INCIDENT_EVENTS_LINKED,
}

SEVERITY_POINTS = {
    Severity.INFO: 10,
    Severity.LOW: 25,
    Severity.MEDIUM: 50,
    Severity.HIGH: 75,
    Severity.CRITICAL: 90,
}


def not_found() -> ApiError:
    return ApiError(404, "not_found", "Not Found")


def view_provenances(view: str) -> tuple[Provenance, ...]:
    return {"live": LIVE, "simulated": SIMULATED}.get(view, tuple(Provenance))


# --- The workflow ------------------------------------------------------------------------------


@dataclass(frozen=True)
class Move:
    to_status: IncidentStatus
    label: str
    resolutions: tuple[Resolution, ...] = ()
    note_required: bool = False
    leads_only: bool = False


def moves_from(status: IncidentStatus) -> list[Move]:
    """Every transition the workflow allows from `status`, before role checks."""
    if status is S.CLOSED:
        return [Move(S.INVESTIGATING, "Reopen", note_required=True, leads_only=True)]
    nxt = FORWARD[status]
    if nxt is S.CLOSED:
        return [
            Move(
                S.CLOSED,
                "Close",
                (*VALIDATED_CLOSE, *EARLY_CLOSE),
                note_required=True,
                leads_only=True,
            ),
            Move(S.REMEDIATION, "Validation failed", note_required=True),
        ]
    return [
        Move(nxt, f"Move to {nxt.value.title()}"),
        Move(
            S.CLOSED, "Close as not an incident", EARLY_CLOSE, note_required=True, leads_only=True
        ),
    ]


def is_lead(user: User) -> bool:
    return user.role in LEADS


def _may_work(user: User, incident: Incident) -> bool:
    return is_lead(user) or (user.role is Role.ANALYST and incident.owner_id == user.id)


def _may_triage_unassigned(user: User, incident: Incident) -> bool:
    return user.role is Role.ANALYST and incident.owner_id is None and incident.status is S.DETECTED


def permissions(user: User, incident: Incident) -> Permissions:
    closed = incident.status is S.CLOSED
    works = _may_work(user, incident)
    moves = [
        AvailableMove(
            to_status=m.to_status,
            label=m.label,
            resolutions=list(m.resolutions),
            note_required=m.note_required,
        )
        for m in moves_from(incident.status)
        if (is_lead(user) or not m.leads_only)
        and (works or (_may_triage_unassigned(user, incident) and m.to_status is S.TRIAGED))
    ]
    writer = user.role in INVESTIGATORS
    return Permissions(
        can_edit=works and not closed,
        can_change_severity=is_lead(user) and not closed,
        can_assign=is_lead(user) and not closed,
        can_take=user.role is Role.ANALYST and incident.owner_id is None and not closed,
        can_add_note=writer,
        can_link_events=works and not closed,
        moves=moves,
    )


# --- Evidence integrity -------------------------------------------------------------------------


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds")


def entry_digest(entry: IncidentTimelineEntry) -> str:
    """SHA-256 of a timeline entry's canonical content: what the audit record commits to."""
    canonical = {
        "id": str(entry.id),
        "incident_id": str(entry.incident_id),
        "at": _iso(entry.at),
        "actor_id": str(entry.actor_id) if entry.actor_id else None,
        "actor_label": entry.actor_label,
        "kind": str(entry.kind),
        "from_status": str(entry.from_status) if entry.from_status else None,
        "to_status": str(entry.to_status) if entry.to_status else None,
        "body": entry.body,
        "details": entry.details,
    }
    text = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(text.encode()).hexdigest()


def verify_timeline(db: Session, incident_id: uuid.UUID) -> Integrity:
    """Each timeline entry must match the digest its audit record committed to, and every
    committed entry must still exist. The audit chain itself is verified separately
    (GET /audit-logs/verify); together they make the timeline tamper-evident."""
    entries = list(
        db.scalars(
            select(IncidentTimelineEntry)
            .where(IncidentTimelineEntry.incident_id == incident_id)
            .order_by(IncidentTimelineEntry.seq)
        ).all()
    )
    committed: dict[str, str] = {}
    for details in db.scalars(
        select(AuditLog.details).where(
            AuditLog.resource_type == "incident", AuditLog.resource_id == str(incident_id)
        )
    ).all():
        if isinstance(details, dict) and "entry" in details:
            committed[str(details["entry"])] = str(details.get("digest"))
    for checked, entry in enumerate(entries):
        if committed.pop(str(entry.id), None) != entry_digest(entry):
            return Integrity(verified=False, entries_checked=checked, first_mismatch=entry.id)
    if committed:  # an audited entry has disappeared from the timeline
        missing = uuid.UUID(next(iter(committed)))
        return Integrity(verified=False, entries_checked=len(entries), first_mismatch=missing)
    return Integrity(verified=True, entries_checked=len(entries), first_mismatch=None)


def append_entry(
    db: Session,
    incident: Incident,
    *,
    kind: TimelineKind,
    actor: User | None,
    ctx: RequestContext,
    body: str | None = None,
    from_status: IncidentStatus | None = None,
    to_status: IncidentStatus | None = None,
    details: dict[str, Any] | None = None,
) -> IncidentTimelineEntry:
    """Append one timeline entry and commit its digest to the audit chain, in the caller's
    transaction."""
    entry = IncidentTimelineEntry(
        id=uuid.uuid4(),
        incident_id=incident.id,
        at=utcnow(),
        actor_id=actor.id if actor else None,
        actor_label=actor.email if actor else SYSTEM_ACTOR,
        kind=kind,
        from_status=from_status,
        to_status=to_status,
        body=body,
        details=bounded(details or {}),
    )
    db.add(entry)
    db.flush()
    audit_details: dict[str, Any] = {
        "reference": incident.reference,
        "entry": str(entry.id),
        "digest": entry_digest(entry),
        "kind": str(kind),
    }
    if from_status or to_status:
        audit_details["transition"] = f"{from_status or '-'} -> {to_status or '-'}"
    audit.record(
        db,
        action=AUDIT_ACTION[kind],
        result=AuditResult.SUCCESS,
        actor=actor if actor else SYSTEM_ACTOR,
        ctx=ctx,
        resource_type="incident",
        resource_id=str(incident.id),
        details=audit_details,
    )
    return entry


def _touch(incident: Incident) -> None:
    incident.version += 1
    incident.updated_at = utcnow()


def link_events(
    db: Session,
    incident: Incident,
    event_ids: Sequence[uuid.UUID],
    *,
    actor: User | None,
    ctx: RequestContext,
) -> list[uuid.UUID]:
    """Attach unlinked events of the incident's provenance. Returns the IDs linked now."""
    if not event_ids:
        return []
    linked = list(
        db.scalars(
            update(SecurityEvent)
            .where(
                SecurityEvent.id.in_(list(event_ids)),
                SecurityEvent.incident_id.is_(None),
                SecurityEvent.provenance == incident.provenance,
            )
            .values(incident_id=incident.id)
            .returning(SecurityEvent.id)
        ).all()
    )
    if linked:
        append_entry(
            db,
            incident,
            kind=TimelineKind.EVENTS_LINKED,
            actor=actor,
            ctx=ctx,
            details={"count": len(linked), "event_ids": [str(i) for i in linked]},
        )
    return linked


# --- Automatic incidents (correlation) ----------------------------------------------------------


def dedupe_key(event: SecurityEvent) -> str:
    """One open incident per attack source, per provenance."""
    if event.source_ip:
        return f"{event.provenance}|ip:{event.source_ip}"
    if event.actor_label:
        return f"{event.provenance}|actor:{event.actor_label}"
    return f"{event.provenance}|category:{event.category}"


def _auto_summary(event: SecurityEvent) -> str:
    evidence = event.evidence or {}
    parts = [f"Opened automatically by the detection engine: {event.title}."]
    if evidence.get("description"):
        parts.append(f"Rule {event.rule_id}: {evidence['description']}.")
    if evidence.get("events"):
        parts.append(
            f"{evidence['events']} events in {evidence.get('window_minutes', '?')} minutes"
            + (
                f" across {evidence['distinct_accounts']} accounts."
                if evidence.get("distinct_accounts", 0) > 1
                else "."
            )
        )
    if event.provenance in SIMULATED:
        parts.append("SIMULATED: generated by the attack simulator; no real attack occurred.")
    return " ".join(parts)[:2000]


def open_or_join(db: Session, event: SecurityEvent) -> Incident:
    """Open an incident for `event`, or attach it to the open incident from the same source.

    Called by correlation (under the audit-chain lock) for detections and single events the
    incident policy selects.
    """
    ctx = RequestContext(correlation_id=event.correlation_id)
    key = dedupe_key(event)
    incident = db.scalar(
        select(Incident)
        .where(Incident.dedupe_key == key, Incident.status.in_(OPEN_STATUSES))
        .order_by(Incident.number.desc())
        .limit(1)
        .with_for_update()
    )
    if incident is None:
        now = utcnow()
        incident = Incident(
            id=uuid.uuid4(),
            title=event.title[:160],
            summary=_auto_summary(event),
            severity=event.severity,
            category=event.category,
            status=S.DETECTED,
            provenance=event.provenance,
            source_ip=event.source_ip,
            detection_rule=event.rule_id,
            trigger_event_id=event.id,
            dedupe_key=key,
            created_by_label=SYSTEM_ACTOR,
            detected_at=event.occurred_at,
            created_at=now,
            updated_at=now,
            version=1,
        )
        db.add(incident)
        db.flush()
        append_entry(
            db,
            incident,
            kind=TimelineKind.CREATED,
            actor=None,
            ctx=ctx,
            to_status=S.DETECTED,
            details={"trigger_event": str(event.id), "rule": event.rule_id, "title": event.title},
        )
    elif event.severity.rank > incident.severity.rank:
        before = incident.severity
        incident.severity = event.severity
        _touch(incident)
        append_entry(
            db,
            incident,
            kind=TimelineKind.SEVERITY_RAISED,
            actor=None,
            ctx=ctx,
            details={"from": str(before), "to": str(event.severity), "event": str(event.id)},
        )
    contributing = [uuid.UUID(i) for i in (event.evidence or {}).get("contributing_event_ids", [])]
    if link_events(db, incident, [event.id, *contributing], actor=None, ctx=ctx):
        _touch(incident)
    return incident


# --- Responses ------------------------------------------------------------------------------------


def _person(user: User | None) -> Person | None:
    if user is None:
        return None
    return Person(id=user.id, display_name=user.display_name, role=user.role)


def risk_score(incident: Incident, events: Sequence[SecurityEvent]) -> RiskScore:
    """Explainable risk: a sum of named factors, capped at 100 (spec §41: no unexplained
    numbers)."""
    factors = [
        RiskFactor(
            reason=f"Severity {incident.severity.value}",
            points=SEVERITY_POINTS[incident.severity],
        )
    ]
    if any(
        e.outcome is Outcome.ALLOWED and e.source is not EventSource.CORRELATION for e in events
    ):
        factors.append(
            RiskFactor(reason="An attack request received a success response", points=10)
        )
    critical = sorted(
        {
            f"{e.method} {e.endpoint}"
            for e in events
            if e.method
            and e.endpoint
            and (policy := ENDPOINTS.get((e.method, e.endpoint))) is not None
            and policy.risk is Risk.CRITICAL
        }
    )
    if critical:
        factors.append(
            RiskFactor(reason=f"Targets a critical-risk endpoint ({critical[0]})", points=5)
        )
    return RiskScore(score=min(100, sum(f.points for f in factors)), factors=factors)


class IncidentService:
    def __init__(self, *, db: Session, ctx: RequestContext) -> None:
        self.db = db
        self.ctx = ctx

    # --- reads --------------------------------------------------------------------------

    def _load(self, incident_id: uuid.UUID, *, for_update: bool = False) -> Incident:
        query = select(Incident).where(Incident.id == incident_id)
        if for_update:
            query = query.with_for_update()
        incident = self.db.scalar(query)
        if incident is None:
            raise not_found()
        return incident

    def _summary(self, incident: Incident, owner: User | None, event_count: int) -> IncidentSummary:
        return IncidentSummary(
            id=incident.id,
            reference=incident.reference,
            title=incident.title,
            severity=incident.severity,
            category=incident.category,
            status=incident.status,
            resolution=incident.resolution,
            provenance=incident.provenance,
            source_ip=incident.source_ip,
            detection_rule=incident.detection_rule,
            owner=_person(owner),
            event_count=event_count,
            detected_at=incident.detected_at,
            created_at=incident.created_at,
            updated_at=incident.updated_at,
            closed_at=incident.closed_at,
        )

    def list_incidents(
        self,
        principal: Principal,
        *,
        view: str,
        state: str,
        min_severity: Severity | None,
        owner: str | None,
        before_number: int | None,
        limit: int,
    ) -> IncidentPage:
        counts = (
            select(SecurityEvent.incident_id, func.count().label("n"))
            .where(SecurityEvent.incident_id.is_not(None))
            .group_by(SecurityEvent.incident_id)
            .subquery()
        )
        query = (
            select(Incident, User, func.coalesce(counts.c.n, 0))
            .outerjoin(User, User.id == Incident.owner_id)
            .outerjoin(counts, counts.c.incident_id == Incident.id)
            .where(Incident.provenance.in_(view_provenances(view)))
            .order_by(Incident.number.desc())
            .limit(limit + 1)
        )
        if state == "open":
            query = query.where(Incident.status.in_(OPEN_STATUSES))
        elif state == "closed":
            query = query.where(Incident.status == S.CLOSED)
        elif state != "all":
            query = query.where(Incident.status == IncidentStatus(state))
        if min_severity is not None:
            query = query.where(
                Incident.severity.in_([s for s in Severity if s.rank >= min_severity.rank])
            )
        if owner == "me":
            query = query.where(Incident.owner_id == principal.user.id)
        elif owner == "unassigned":
            query = query.where(Incident.owner_id.is_(None))
        if before_number is not None:
            query = query.where(Incident.number < before_number)
        rows = self.db.execute(query).all()
        has_more = len(rows) > limit
        rows = rows[:limit]
        return IncidentPage(
            items=[self._summary(i, u, n) for i, u, n in rows],
            next_before_number=rows[-1][0].number if has_more and rows else None,
        )

    def detail(self, principal: Principal, incident_id: uuid.UUID) -> IncidentDetail:
        incident = self._load(incident_id)
        return self._detail(principal, incident)

    def _detail(self, principal: Principal, incident: Incident) -> IncidentDetail:
        owner = self.db.get(User, incident.owner_id) if incident.owner_id else None
        events = list(
            self.db.scalars(
                select(SecurityEvent)
                .where(SecurityEvent.incident_id == incident.id)
                .order_by(SecurityEvent.occurred_at.desc(), SecurityEvent.seq.desc())
                .limit(MAX_EVENTS)
            ).all()
        )
        event_count = (
            self.db.scalar(
                select(func.count())
                .select_from(SecurityEvent)
                .where(SecurityEvent.incident_id == incident.id)
            )
            or 0
        )
        trigger = (
            self.db.scalar(
                select(SecurityEvent).where(SecurityEvent.id == incident.trigger_event_id)
            )
            if incident.trigger_event_id
            else None
        )
        timeline = list(
            self.db.scalars(
                select(IncidentTimelineEntry)
                .where(IncidentTimelineEntry.incident_id == incident.id)
                .order_by(IncidentTimelineEntry.seq)
                .limit(MAX_TIMELINE)
            ).all()
        )
        summary = self._summary(incident, owner, event_count)
        return IncidentDetail(
            **summary.model_dump(),
            summary=incident.summary,
            remediation=incident.remediation,
            version=incident.version,
            created_by_label=incident.created_by_label,
            trigger_event=(
                EventDetail.model_validate(trigger, from_attributes=True) if trigger else None
            ),
            events=[EventSummary.model_validate(e, from_attributes=True) for e in events],
            timeline=[TimelineEntry.model_validate(t, from_attributes=True) for t in timeline],
            risk=risk_score(incident, events),
            integrity=verify_timeline(self.db, incident.id),
            permissions=permissions(principal.user, incident),
        )

    def assignees(self) -> AssigneeList:
        users = self.db.scalars(
            select(User)
            .where(User.is_active, User.role.in_(sorted(INVESTIGATORS)))
            .order_by(User.display_name)
        ).all()
        return AssigneeList(items=[p for u in users if (p := _person(u)) is not None])

    # --- guards -------------------------------------------------------------------------

    def _deny(
        self, principal: Principal, incident: Incident, reason: str, message: str
    ) -> ApiError:
        """Refuse and audit: acting on another analyst's incident is an authorization event."""
        audit.record(
            self.db,
            action=AuditAction.ACCESS_DENIED,
            result=AuditResult.DENIED,
            actor=principal.user,
            ctx=self.ctx,
            resource_type="incident",
            resource_id=str(incident.id),
            details={"reason": reason, "reference": incident.reference},
        )
        self.db.commit()
        return ApiError(403, "forbidden", message)

    def _require_work(self, principal: Principal, incident: Incident) -> None:
        if not _may_work(principal.user, incident):
            raise self._deny(
                principal,
                incident,
                "not_owner",
                "This incident is assigned to someone else. Take it or ask a lead to assign it.",
            )

    def _require_lead(self, principal: Principal, incident: Incident, what: str) -> None:
        if not is_lead(principal.user):
            raise self._deny(
                principal,
                incident,
                "lead_required",
                f"Only a security engineer or admin can {what}.",
            )

    @staticmethod
    def _check_version(incident: Incident, version: int) -> None:
        if incident.version != version:
            raise ApiError(
                409,
                "stale_version",
                "The incident changed since you loaded it. Reload and try again.",
            )

    @staticmethod
    def _require_open(incident: Incident) -> None:
        if incident.status is S.CLOSED:
            raise ApiError(409, "incident_closed", "The incident is closed. Reopen it first.")

    def _events_for_linking(self, event_ids: Sequence[uuid.UUID]) -> list[SecurityEvent]:
        unique = list(dict.fromkeys(event_ids))
        events = list(
            self.db.scalars(select(SecurityEvent).where(SecurityEvent.id.in_(unique))).all()
        )
        if len(events) != len(unique):
            raise ApiError(422, "unknown_event", "One or more events do not exist.")
        if any(e.incident_id is not None for e in events):
            raise ApiError(
                409, "event_already_linked", "An event can be evidence for one incident only."
            )
        return events

    # --- writes -------------------------------------------------------------------------

    def create(self, principal: Principal, body: IncidentCreate) -> IncidentDetail:
        events = self._events_for_linking(body.event_ids)
        provenances = {e.provenance for e in events}
        if len(provenances) > 1:
            raise ApiError(
                422,
                "mixed_provenance",
                "Simulated and real events cannot be evidence for the same incident.",
            )
        provenance = provenances.pop() if provenances else Provenance.LOCAL
        now = utcnow()
        first = min(events, key=lambda e: e.occurred_at) if events else None
        incident = Incident(
            id=uuid.uuid4(),
            title=body.title,
            summary=body.summary,
            severity=body.severity,
            category=body.category,
            status=S.DETECTED,
            provenance=provenance,
            source_ip=first.source_ip if first else None,
            trigger_event_id=first.id if first else None,
            owner_id=principal.user.id,
            created_by_label=principal.user.email,
            detected_at=first.occurred_at if first else now,
            created_at=now,
            updated_at=now,
            version=1,
        )
        self.db.add(incident)
        self.db.flush()
        append_entry(
            self.db,
            incident,
            kind=TimelineKind.CREATED,
            actor=principal.user,
            ctx=self.ctx,
            to_status=S.DETECTED,
            details={"manual": True, "owner": principal.user.email},
        )
        link_events(self.db, incident, [e.id for e in events], actor=principal.user, ctx=self.ctx)
        self.db.commit()
        return self._detail(principal, incident)

    def update(
        self, principal: Principal, incident_id: uuid.UUID, body: IncidentUpdate
    ) -> IncidentDetail:
        incident = self._load(incident_id, for_update=True)
        self._require_work(principal, incident)
        self._require_open(incident)
        self._check_version(incident, body.version)
        changes = body.model_dump(exclude_none=True, exclude={"version"})
        if "severity" in changes and changes["severity"] != incident.severity:
            self._require_lead(principal, incident, "change an incident's severity")
        before = {k: getattr(incident, k) for k in changes}
        changed = {k: v for k, v in changes.items() if before[k] != v}
        if not changed:
            return self._detail(principal, incident)
        for key, value in changed.items():
            setattr(incident, key, value)
        _touch(incident)
        append_entry(
            self.db,
            incident,
            kind=TimelineKind.UPDATED,
            actor=principal.user,
            ctx=self.ctx,
            details={
                "fields": sorted(changed),
                **(
                    {"severity": f"{before['severity']} -> {changed['severity']}"}
                    if "severity" in changed
                    else {}
                ),
            },
        )
        self.db.commit()
        return self._detail(principal, incident)

    def transition(
        self, principal: Principal, incident_id: uuid.UUID, body: TransitionRequest
    ) -> IncidentDetail:
        incident = self._load(incident_id, for_update=True)
        user = principal.user
        triaging_unassigned = _may_triage_unassigned(user, incident) and body.to_status is S.TRIAGED
        if not triaging_unassigned:
            self._require_work(principal, incident)
        self._check_version(incident, body.version)

        moves = moves_from(incident.status)
        move = next((m for m in moves if m.to_status is body.to_status), None)
        if move is None:
            allowed = ", ".join(sorted({m.to_status.value for m in moves}))
            raise ApiError(
                409,
                "invalid_transition",
                f"{incident.status.value} cannot move to {body.to_status.value}. "
                f"Allowed: {allowed}.",
            )
        if move.leads_only:
            self._require_lead(principal, incident, f"{move.label.lower()} an incident")
        if move.resolutions and body.resolution is None:
            raise ApiError(422, "resolution_required", "Choose a resolution to close the incident.")
        if move.resolutions and body.resolution not in move.resolutions:
            raise ApiError(
                422,
                "resolution_not_available",
                "Closing as resolved or accepted risk is possible only after validation.",
            )
        if not move.resolutions and body.resolution is not None:
            raise ApiError(422, "unexpected_resolution", "A resolution applies only to closing.")
        if move.note_required and not body.note:
            raise ApiError(422, "note_required", f"{move.label} needs a note explaining why.")
        if body.resolution in VALIDATED_CLOSE and not (incident.remediation or "").strip():
            raise ApiError(
                422,
                "remediation_required",
                "Record the remediation before closing the incident as resolved.",
            )

        before = incident.status
        if triaging_unassigned or (body.to_status is S.TRIAGED and incident.owner_id is None):
            incident.owner_id = user.id
            append_entry(
                self.db,
                incident,
                kind=TimelineKind.ASSIGNED,
                actor=user,
                ctx=self.ctx,
                details={"owner": user.email, "reason": "triage"},
            )
        incident.status = body.to_status
        if body.to_status is S.CLOSED:
            incident.resolution = body.resolution
            incident.closed_at = utcnow()
        elif before is S.CLOSED:  # reopened
            incident.resolution = None
            incident.closed_at = None
        _touch(incident)
        append_entry(
            self.db,
            incident,
            kind=TimelineKind.STATUS_CHANGED,
            actor=user,
            ctx=self.ctx,
            from_status=before,
            to_status=body.to_status,
            body=body.note,
            details={"resolution": str(body.resolution)} if body.resolution else {},
        )
        self.db.commit()
        return self._detail(principal, incident)

    def assign(
        self, principal: Principal, incident_id: uuid.UUID, body: AssignmentRequest
    ) -> IncidentDetail:
        incident = self._load(incident_id, for_update=True)
        user = principal.user
        taking = (
            user.role is Role.ANALYST and body.owner_id == user.id and incident.owner_id is None
        )
        if not taking:
            self._require_lead(principal, incident, "assign incidents to other people")
        self._require_open(incident)
        self._check_version(incident, body.version)
        new_owner: User | None = None
        if body.owner_id is not None:
            new_owner = self.db.get(User, body.owner_id)
            if new_owner is None or not new_owner.is_active or new_owner.role not in INVESTIGATORS:
                raise ApiError(
                    422,
                    "invalid_assignee",
                    "Assign to an active administrator, security engineer or analyst.",
                )
        if incident.owner_id == body.owner_id:
            return self._detail(principal, incident)
        incident.owner_id = body.owner_id
        _touch(incident)
        append_entry(
            self.db,
            incident,
            kind=TimelineKind.ASSIGNED,
            actor=user,
            ctx=self.ctx,
            details={"owner": new_owner.email if new_owner else None},
        )
        self.db.commit()
        return self._detail(principal, incident)

    def add_note(
        self, principal: Principal, incident_id: uuid.UUID, body: NoteCreate
    ) -> IncidentDetail:
        incident = self._load(incident_id, for_update=True)
        append_entry(
            self.db,
            incident,
            kind=TimelineKind.NOTE,
            actor=principal.user,
            ctx=self.ctx,
            body=body.body,
        )
        incident.updated_at = utcnow()
        self.db.commit()
        return self._detail(principal, incident)

    def link(
        self, principal: Principal, incident_id: uuid.UUID, body: LinkEventsRequest
    ) -> IncidentDetail:
        incident = self._load(incident_id, for_update=True)
        self._require_work(principal, incident)
        self._require_open(incident)
        self._check_version(incident, body.version)
        events = self._events_for_linking(body.event_ids)
        if any(e.provenance is not incident.provenance for e in events):
            raise ApiError(
                422,
                "mixed_provenance",
                "Simulated and real events cannot be evidence for the same incident.",
            )
        if link_events(
            self.db, incident, [e.id for e in events], actor=principal.user, ctx=self.ctx
        ):
            _touch(incident)
        self.db.commit()
        return self._detail(principal, incident)
