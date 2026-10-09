"""Security exceptions and change management (spec §38, §39; ADR-0023).

Separation of duties: whoever asks cannot approve. The service refuses it (409
`separation_of_duties`), the response tells the UI so it can explain why, and a CHECK
constraint refuses it again in the database. On a single-maintainer project this means a second
lead account; that is the point.

Exceptions (EXC-n): requested by a lead or a developer (developers for applications they own),
decided by a different lead, with an expiry no further away than the risk allows (critical 30
days, high 90, medium 180, low 365). An approved exception expires on its date (the sweep runs on
every read and write, so it never depends on a scheduler) or is closed early when the issue is
fixed. Approved `scan_finding` exceptions become the scan gate's accepted-risk register
(`accepted_risks_toml`, `make accepted-risks`): the application is the system of record, the
file in the repository is generated from it.

Change requests (CHG-n): submitted with a rollback plan and a validation plan, approved by a
different lead, implemented (with a reference such as a pull request), then validated or rolled
back. A `waf_rule` change drives the SIMULATED WAF when implemented and restores the previous
mode when rolled back; real WAF rules change only through reviewed Terraform (ADR-0008).

History: each record's timeline is read from the hash-chained audit log, where every step is
recorded in the same transaction as the step itself.
"""

from __future__ import annotations

import json
import uuid
from collections import Counter
from datetime import date, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.authz import Principal
from app.core.clock import utcnow
from app.core.errors import ApiError
from app.models.application import Application, AppStatus
from app.models.audit import AuditLog, AuditResult
from app.models.governance import Control
from app.models.risk_governance import (
    MAX_EXCEPTION_DAYS,
    ChangeRequest,
    ChangeStatus,
    ChangeType,
    ExceptionScope,
    ExceptionStatus,
    SecurityException,
)
from app.models.simulation import WafMode
from app.models.user import Role
from app.schemas.risk_governance import (
    AppRef,
    ChangeCounts,
    ChangeCreate,
    ChangeDetail,
    ChangeList,
    ChangeSummary,
    ChangeTransition,
    ExceptionClose,
    ExceptionCounts,
    ExceptionCreate,
    ExceptionDecision,
    ExceptionDetail,
    ExceptionList,
    ExceptionPermissions,
    ExceptionSummary,
    HistoryEntry,
)
from app.services import audit
from app.services.audit import SYSTEM_CONTEXT, AuditAction, RequestContext
from app.services.governance import sync_catalogue
from app.services.simulator import apply_waf_mode, waf_rule_ids

LEADS = frozenset({Role.ADMIN, Role.SECURITY_ENGINEER})
SEES_ALL = frozenset({Role.ADMIN, Role.SECURITY_ENGINEER, Role.ANALYST, Role.VIEWER})
SYSTEM_ACTOR = "system:governance"
NOTE_MIN = 10

_EXCEPTION_ACTION = {
    ExceptionStatus.APPROVED: AuditAction.EXCEPTION_APPROVED,
    ExceptionStatus.REJECTED: AuditAction.EXCEPTION_REJECTED,
    ExceptionStatus.WITHDRAWN: AuditAction.EXCEPTION_WITHDRAWN,
    ExceptionStatus.CLOSED: AuditAction.EXCEPTION_CLOSED,
}
_CHANGE_ACTION = {
    ChangeStatus.APPROVED: AuditAction.CHANGE_APPROVED,
    ChangeStatus.REJECTED: AuditAction.CHANGE_REJECTED,
    ChangeStatus.CANCELLED: AuditAction.CHANGE_CANCELLED,
    ChangeStatus.IMPLEMENTED: AuditAction.CHANGE_IMPLEMENTED,
    ChangeStatus.VALIDATED: AuditAction.CHANGE_VALIDATED,
    ChangeStatus.ROLLED_BACK: AuditAction.CHANGE_ROLLED_BACK,
}
# Moves that end or reverse work need a reason.
_NEEDS_NOTE = frozenset(
    {
        ChangeStatus.REJECTED,
        ChangeStatus.CANCELLED,
        ChangeStatus.VALIDATED,
        ChangeStatus.ROLLED_BACK,
    }
)


def today() -> date:
    return utcnow().date()


def expire_exceptions(db: Session) -> int:
    """Approved exceptions past their expiry date expire (audited). The caller commits."""
    due = list(
        db.scalars(
            select(SecurityException)
            .where(
                SecurityException.status == ExceptionStatus.APPROVED,
                SecurityException.expires_on < today(),
            )
            .with_for_update(skip_locked=True)
        )
    )
    now = utcnow()
    for e in due:
        e.status = ExceptionStatus.EXPIRED
        e.ended_at = now
        e.end_note = f"Expired on {e.expires_on.isoformat()}: the risk is no longer accepted."
        e.updated_at = now
        e.version += 1
        audit.record(
            db,
            action=AuditAction.EXCEPTION_EXPIRED,
            result=AuditResult.SUCCESS,
            actor=SYSTEM_ACTOR,
            ctx=SYSTEM_CONTEXT,
            resource_type="exception",
            resource_id=str(e.id),
            details={"exception": e.reference, "expires_on": e.expires_on.isoformat()},
        )
    return len(due)


def _toml_string(value: str) -> str:
    # JSON string escapes are valid TOML basic-string escapes.
    return json.dumps(value, ensure_ascii=False)


def accepted_risks_toml(db: Session) -> str:
    """The scan gate's accepted-risk register, generated from approved, unexpired
    `scan_finding` exceptions of SentinelEdge itself (scanning/accepted-findings.toml)."""
    expire_exceptions(db)
    rows = db.scalars(
        select(SecurityException)
        .join(Application, Application.id == SecurityException.application_id)
        .where(
            Application.is_platform,
            SecurityException.scope == ExceptionScope.SCAN_FINDING,
            SecurityException.status == ExceptionStatus.APPROVED,
        )
        .order_by(SecurityException.number)
    )
    lines = [
        "# Accepted risks for the scan gate (ADR-0020, ADR-0023).",
        "#",
        "# GENERATED by `make accepted-risks` from the approved scan-finding exceptions in",
        "# SentinelEdge (Compliance > Exceptions). Do not edit by hand: request an exception in",
        "# the application, have a different lead approve it, regenerate and commit this file.",
        "# After its expiry date an entry covers nothing and the finding blocks again.",
    ]
    for e in rows:
        match = e.gate_match or {}
        pairs = ", ".join(f"{k} = {_toml_string(v)}" for k, v in sorted(match.items()) if v)
        lines += [
            "",
            "[[accepted]]",
            f"id = {_toml_string(e.reference)}",
            f"match = {{ {pairs} }}",
            f"justification = {_toml_string(e.justification)}",
            f"compensating_control = {_toml_string(e.compensating_control)}",
            f"approver = {_toml_string(e.approver_label or '')}",
            f"expires = {e.expires_on.isoformat()}",
        ]
    return "\n".join(lines) + "\n"


class RiskGovernanceService:
    def __init__(self, *, db: Session, ctx: RequestContext) -> None:
        self.db = db
        self.ctx = ctx

    # --- access -----------------------------------------------------------------------------

    def _sweep(self) -> None:
        if expire_exceptions(self.db):
            self.db.commit()

    def _deny(self, principal: Principal, resource_type: str, resource_id: uuid.UUID) -> ApiError:
        audit.record(
            self.db,
            action=AuditAction.ACCESS_DENIED,
            result=AuditResult.DENIED,
            actor=principal.user,
            ctx=self.ctx,
            resource_type=resource_type,
            resource_id=str(resource_id),
            details={"reason": "not_owner"},
        )
        self.db.commit()
        return ApiError(404, "not_found", "Not Found")

    def _visible(self, principal: Principal, app: Application) -> bool:
        return principal.user.role in SEES_ALL or app.owner_id == principal.user.id

    def _app(self, principal: Principal, app_id: uuid.UUID | None) -> Application:
        """The application a new request is about: SentinelEdge itself by default. Developers
        may only raise requests for applications they own."""
        if app_id is None:
            app = self.db.scalar(select(Application).where(Application.is_platform))
        else:
            app = self.db.get(Application, app_id)
        if app is None:
            raise ApiError(422, "unknown_application", "No such application.")
        if not self._visible(principal, app):
            raise self._deny(principal, "application", app.id)
        if app.status is not AppStatus.ACTIVE:
            raise ApiError(409, "application_retired", "The application is retired.")
        return app

    @staticmethod
    def _app_ref(app: Application) -> AppRef:
        return AppRef(id=app.id, slug=app.slug, name=app.name)

    def _history(self, resource_type: str, resource_id: uuid.UUID) -> list[HistoryEntry]:
        rows = self.db.scalars(
            select(AuditLog)
            .where(
                AuditLog.resource_type == resource_type, AuditLog.resource_id == str(resource_id)
            )
            .order_by(AuditLog.seq)
        )
        return [
            HistoryEntry(
                seq=r.seq,
                occurred_at=r.occurred_at,
                action=r.action,
                actor_label=r.actor_label,
                note=(r.details or {}).get("note"),
            )
            for r in rows
        ]

    def _audit(
        self,
        action: AuditAction,
        principal: Principal,
        resource_type: str,
        record: SecurityException | ChangeRequest,
        **details: Any,
    ) -> None:
        audit.record(
            self.db,
            action=action,
            result=AuditResult.SUCCESS,
            actor=principal.user,
            ctx=self.ctx,
            resource_type=resource_type,
            resource_id=str(record.id),
            details={"reference": record.reference, **details},
        )

    @staticmethod
    def _note(note: str, what: str) -> str:
        if len(note) < NOTE_MIN:
            raise ApiError(
                422, "note_required", f"Explain {what} in a note of at least {NOTE_MIN} characters."
            )
        return note

    # --- exceptions -------------------------------------------------------------------------

    def _exception(
        self, principal: Principal, exception_id: uuid.UUID, *, lock: bool = False
    ) -> tuple[SecurityException, Application]:
        e = self.db.get(SecurityException, exception_id, with_for_update=lock)
        if e is None:
            raise ApiError(404, "not_found", "Not Found")
        app = self.db.get(Application, e.application_id)
        assert app is not None  # noqa: S101 - foreign key  # nosec B101
        if not self._visible(principal, app):
            raise self._deny(principal, "exception", e.id)
        return e, app

    @staticmethod
    def _is_requester(principal: Principal, record: SecurityException | ChangeRequest) -> bool:
        return record.requester_id == principal.user.id

    def _exception_permissions(
        self, principal: Principal, e: SecurityException
    ) -> ExceptionPermissions:
        lead = principal.user.role in LEADS
        mine = self._is_requester(principal, e)
        pending = e.status is ExceptionStatus.REQUESTED
        return ExceptionPermissions(
            can_decide=lead and pending and not mine,
            can_close=e.status in (ExceptionStatus.REQUESTED, ExceptionStatus.APPROVED)
            and (lead or mine),
            separation_of_duties=lead and pending and mine,
        )

    def _exception_summary(self, e: SecurityException, app: Application) -> ExceptionSummary:
        days = (e.expires_on - today()).days if e.status is ExceptionStatus.APPROVED else None
        return ExceptionSummary(
            id=e.id,
            reference=e.reference,
            title=e.title,
            application=self._app_ref(app),
            scope=e.scope,
            scope_ref=e.scope_ref,
            risk_level=e.risk_level,
            status=e.status,
            requester_label=e.requester_label,
            approver_label=e.approver_label,
            expires_on=e.expires_on,
            days_left=days,
            imported=e.imported,
            version=e.version,
        )

    def _exception_detail(
        self, principal: Principal, e: SecurityException, app: Application
    ) -> ExceptionDetail:
        return ExceptionDetail(
            **self._exception_summary(e, app).model_dump(),
            gate_match=e.gate_match,
            risk=e.risk,
            justification=e.justification,
            compensating_control=e.compensating_control,
            control_refs=list(e.control_refs),
            implementation=e.implementation,
            exit_criteria=e.exit_criteria,
            decided_at=e.decided_at,
            decision_note=e.decision_note,
            ended_at=e.ended_at,
            end_note=e.end_note,
            max_days=MAX_EXCEPTION_DAYS[e.risk_level],
            created_at=e.created_at,
            permissions=self._exception_permissions(principal, e),
            history=self._history("exception", e.id),
        )

    def list_exceptions(
        self, principal: Principal, status: ExceptionStatus | None = None
    ) -> ExceptionList:
        self._sweep()
        query = (
            select(SecurityException, Application)
            .join(Application, Application.id == SecurityException.application_id)
            .order_by(SecurityException.number.desc())
        )
        if principal.user.role not in SEES_ALL:
            query = query.where(Application.owner_id == principal.user.id)
        rows = self.db.execute(query).all()
        counts = Counter(str(e.status) for e, _ in rows)
        soon = today() + timedelta(days=30)
        counts["expiring_30d"] = sum(
            1 for e, _ in rows if e.status is ExceptionStatus.APPROVED and e.expires_on <= soon
        )
        return ExceptionList(
            items=[
                self._exception_summary(e, app)
                for e, app in rows
                if status is None or e.status is status
            ],
            counts=ExceptionCounts(**counts),
        )

    def get_exception(self, principal: Principal, exception_id: uuid.UUID) -> ExceptionDetail:
        self._sweep()
        e, app = self._exception(principal, exception_id)
        return self._exception_detail(principal, e, app)

    def _known_controls(self, refs: list[str]) -> list[str]:
        if sync_catalogue(self.db):
            self.db.flush()
        wanted = sorted(set(refs))
        found = set(
            self.db.scalars(select(Control.ref).where(Control.ref.in_(wanted), ~Control.retired))
        )
        if missing := [r for r in wanted if r not in found]:
            raise ApiError(422, "unknown_control", f"No such control: {', '.join(missing)}")
        return wanted

    def request_exception(self, principal: Principal, body: ExceptionCreate) -> ExceptionDetail:
        self._sweep()
        app = self._app(principal, body.application_id)
        if body.scope is ExceptionScope.SCAN_FINDING and not app.is_platform:
            raise ApiError(
                422,
                "gate_is_platform_only",
                "The scan gate covers SentinelEdge's own repository: scan-finding exceptions "
                "belong to SentinelEdge.",
            )
        limit = MAX_EXCEPTION_DAYS[body.risk_level]
        if body.expires_on <= today():
            raise ApiError(422, "expiry_in_past", "The expiry must be in the future.")
        if body.expires_on > today() + timedelta(days=limit):
            raise ApiError(
                422,
                "expiry_too_long",
                f"A {body.risk_level} risk can be accepted for at most {limit} days.",
            )
        controls = self._known_controls(body.control_refs)
        now = utcnow()
        e = SecurityException(
            id=uuid.uuid4(),
            application_id=app.id,
            title=body.title,
            scope=body.scope,
            scope_ref=body.scope_ref,
            gate_match=body.gate_match.model_dump(exclude_none=True) if body.gate_match else None,
            risk_level=body.risk_level,
            risk=body.risk,
            justification=body.justification,
            compensating_control=body.compensating_control,
            control_refs=controls,
            implementation=body.implementation,
            exit_criteria=body.exit_criteria,
            expires_on=body.expires_on,
            status=ExceptionStatus.REQUESTED,
            requester_id=principal.user.id,
            requester_label=principal.user.email,
            imported=False,
            created_at=now,
            updated_at=now,
            version=1,
        )
        self.db.add(e)
        self.db.flush()
        self._audit(
            AuditAction.EXCEPTION_REQUESTED,
            principal,
            "exception",
            e,
            application=app.slug,
            risk_level=str(e.risk_level),
            expires_on=e.expires_on.isoformat(),
        )
        self.db.commit()
        return self._exception_detail(principal, e, app)

    def _locked_exception(
        self, principal: Principal, exception_id: uuid.UUID, version: int
    ) -> tuple[SecurityException, Application]:
        expire_exceptions(self.db)
        e, app = self._exception(principal, exception_id, lock=True)
        if e.version != version:
            raise ApiError(409, "stale_version", "The exception changed since you loaded it.")
        return e, app

    def decide_exception(
        self, principal: Principal, exception_id: uuid.UUID, body: ExceptionDecision
    ) -> ExceptionDetail:
        e, app = self._locked_exception(principal, exception_id, body.version)
        if e.status is not ExceptionStatus.REQUESTED:
            raise ApiError(409, "invalid_transition", f"The exception is already {e.status}.")
        if self._is_requester(principal, e):
            raise ApiError(
                409,
                "separation_of_duties",
                "You requested this exception, so another lead must decide it.",
            )
        if body.approve and e.expires_on <= today():
            raise ApiError(
                409, "expired_before_decision", "Its expiry has passed; request it again."
            )
        if not body.approve:
            self._note(body.note, "why it is rejected")
        e.status = ExceptionStatus.APPROVED if body.approve else ExceptionStatus.REJECTED
        e.approver_id = principal.user.id
        e.approver_label = principal.user.email
        e.decided_at = utcnow()
        e.decision_note = body.note or None
        e.updated_at = e.decided_at
        e.version += 1
        self._audit(_EXCEPTION_ACTION[e.status], principal, "exception", e, note=body.note or None)
        self.db.commit()
        return self._exception_detail(principal, e, app)

    def close_exception(
        self, principal: Principal, exception_id: uuid.UUID, body: ExceptionClose
    ) -> ExceptionDetail:
        e, app = self._locked_exception(principal, exception_id, body.version)
        if not self._exception_permissions(principal, e).can_close:
            raise ApiError(
                409,
                "invalid_transition",
                f"A {e.status} exception cannot be closed here, or not by you.",
            )
        e.status = (
            ExceptionStatus.WITHDRAWN
            if e.status is ExceptionStatus.REQUESTED
            else ExceptionStatus.CLOSED
        )
        e.ended_at = utcnow()
        e.end_note = body.note
        e.updated_at = e.ended_at
        e.version += 1
        self._audit(_EXCEPTION_ACTION[e.status], principal, "exception", e, note=body.note)
        self.db.commit()
        return self._exception_detail(principal, e, app)

    # --- change requests --------------------------------------------------------------------

    def _change(
        self, principal: Principal, change_id: uuid.UUID, *, lock: bool = False
    ) -> tuple[ChangeRequest, Application]:
        c = self.db.get(ChangeRequest, change_id, with_for_update=lock)
        if c is None:
            raise ApiError(404, "not_found", "Not Found")
        app = self.db.get(Application, c.application_id)
        assert app is not None  # noqa: S101 - foreign key  # nosec B101
        if not self._visible(principal, app):
            raise self._deny(principal, "change_request", c.id)
        return c, app

    def available_moves(self, principal: Principal, c: ChangeRequest) -> list[ChangeStatus]:
        lead = principal.user.role in LEADS
        mine = self._is_requester(principal, c)
        moves: list[ChangeStatus] = []
        if c.status is ChangeStatus.SUBMITTED:
            if lead and not mine:
                moves += [ChangeStatus.APPROVED, ChangeStatus.REJECTED]
            if lead or mine:
                moves.append(ChangeStatus.CANCELLED)
        elif c.status is ChangeStatus.APPROVED and (lead or mine):
            moves.append(ChangeStatus.IMPLEMENTED)
        elif c.status is ChangeStatus.IMPLEMENTED:
            if lead:
                moves.append(ChangeStatus.VALIDATED)
            if lead or mine:
                moves.append(ChangeStatus.ROLLED_BACK)
        return moves

    def _change_summary(self, c: ChangeRequest, app: Application) -> ChangeSummary:
        return ChangeSummary(
            id=c.id,
            reference=c.reference,
            title=c.title,
            application=self._app_ref(app),
            change_type=c.change_type,
            risk_level=c.risk_level,
            status=c.status,
            requester_label=c.requester_label,
            approver_label=c.approver_label,
            created_at=c.created_at,
            updated_at=c.updated_at,
            version=c.version,
        )

    def _change_detail(
        self, principal: Principal, c: ChangeRequest, app: Application
    ) -> ChangeDetail:
        return ChangeDetail(
            **self._change_summary(c, app).model_dump(),
            description=c.description,
            impact=c.impact,
            rollback_plan=c.rollback_plan,
            validation_plan=c.validation_plan,
            target=c.target,
            previous_state=c.previous_state,
            decided_at=c.decided_at,
            decision_note=c.decision_note,
            implemented_at=c.implemented_at,
            implemented_by_label=c.implemented_by_label,
            implementation_ref=c.implementation_ref,
            closed_at=c.closed_at,
            closing_note=c.closing_note,
            available_moves=self.available_moves(principal, c),
            separation_of_duties=principal.user.role in LEADS
            and c.status is ChangeStatus.SUBMITTED
            and self._is_requester(principal, c),
            history=self._history("change_request", c.id),
        )

    def list_changes(self, principal: Principal, status: ChangeStatus | None = None) -> ChangeList:
        query = (
            select(ChangeRequest, Application)
            .join(Application, Application.id == ChangeRequest.application_id)
            .order_by(ChangeRequest.number.desc())
        )
        if principal.user.role not in SEES_ALL:
            query = query.where(Application.owner_id == principal.user.id)
        rows = self.db.execute(query).all()
        return ChangeList(
            items=[
                self._change_summary(c, app)
                for c, app in rows
                if status is None or c.status is status
            ],
            counts=ChangeCounts(**Counter(str(c.status) for c, _ in rows)),
        )

    def get_change(self, principal: Principal, change_id: uuid.UUID) -> ChangeDetail:
        c, app = self._change(principal, change_id)
        return self._change_detail(principal, c, app)

    def submit_change(self, principal: Principal, body: ChangeCreate) -> ChangeDetail:
        app = self._app(principal, body.application_id)
        target = None
        if body.target is not None:
            if not app.is_platform:
                raise ApiError(
                    422,
                    "waf_is_platform_only",
                    "The simulated WAF protects SentinelEdge itself.",
                )
            if body.target.rule_id not in waf_rule_ids():
                raise ApiError(422, "unknown_waf_rule", f"No such WAF rule: {body.target.rule_id}")
            target = {"rule_id": body.target.rule_id, "mode": body.target.mode.value}
        now = utcnow()
        c = ChangeRequest(
            id=uuid.uuid4(),
            application_id=app.id,
            title=body.title,
            change_type=body.change_type,
            description=body.description,
            risk_level=body.risk_level,
            impact=body.impact,
            rollback_plan=body.rollback_plan,
            validation_plan=body.validation_plan,
            target=target,
            status=ChangeStatus.SUBMITTED,
            requester_id=principal.user.id,
            requester_label=principal.user.email,
            created_at=now,
            updated_at=now,
            version=1,
        )
        self.db.add(c)
        self.db.flush()
        self._audit(
            AuditAction.CHANGE_SUBMITTED,
            principal,
            "change_request",
            c,
            application=app.slug,
            change_type=str(c.change_type),
            risk_level=str(c.risk_level),
            target=target,
        )
        self.db.commit()
        return self._change_detail(principal, c, app)

    def transition_change(
        self, principal: Principal, change_id: uuid.UUID, body: ChangeTransition
    ) -> ChangeDetail:
        c, app = self._change(principal, change_id, lock=True)
        if c.version != body.version:
            raise ApiError(409, "stale_version", "The change request changed since you loaded it.")
        if body.to not in self.available_moves(principal, c):
            if (
                body.to in (ChangeStatus.APPROVED, ChangeStatus.REJECTED)
                and c.status is ChangeStatus.SUBMITTED
                and self._is_requester(principal, c)
            ):
                raise ApiError(
                    409,
                    "separation_of_duties",
                    "You submitted this change, so another lead must decide it.",
                )
            raise ApiError(
                409,
                "invalid_transition",
                f"A {c.status} change cannot be moved to {body.to} here, or not by you.",
            )
        if body.to in _NEEDS_NOTE:
            self._note(body.note, "this step")
        now = utcnow()
        details: dict[str, Any] = {"note": body.note or None, "from": str(c.status)}
        if body.to in (ChangeStatus.APPROVED, ChangeStatus.REJECTED):
            c.approver_id = principal.user.id
            c.approver_label = principal.user.email
            c.decided_at = now
            c.decision_note = body.note or None
        if body.to is ChangeStatus.IMPLEMENTED:
            if c.change_type is ChangeType.WAF_RULE:
                assert c.target is not None  # noqa: S101 - constraint waf_target  # nosec B101
                before = apply_waf_mode(
                    self.db,
                    principal.user,
                    c.target["rule_id"],
                    WafMode(c.target["mode"]),
                    self.ctx,
                    change=c.reference,
                )
                c.previous_state = {"mode": before.value}
                c.implementation_ref = (
                    body.implementation_ref or f"simulated-waf:{c.target['rule_id']}"
                )
                details["waf"] = {
                    "rule_id": c.target["rule_id"],
                    "from": before.value,
                    "to": c.target["mode"],
                }
            else:
                if not body.implementation_ref:
                    raise ApiError(
                        422,
                        "implementation_ref_required",
                        "Name what implemented the change: a pull request URL or a commit.",
                    )
                c.implementation_ref = body.implementation_ref
            c.implemented_at = now
            c.implemented_by_label = principal.user.email
            details["implementation_ref"] = c.implementation_ref
        if body.to is ChangeStatus.ROLLED_BACK and c.change_type is ChangeType.WAF_RULE:
            assert c.target is not None and c.previous_state is not None  # noqa: S101, PT018  # nosec B101
            apply_waf_mode(
                self.db,
                principal.user,
                c.target["rule_id"],
                WafMode(c.previous_state["mode"]),
                self.ctx,
                change=c.reference,
            )
            details["waf"] = {"rule_id": c.target["rule_id"], "restored": c.previous_state["mode"]}
        if body.to in _NEEDS_NOTE:
            c.closed_at = now
            c.closing_note = body.note
        c.status = body.to
        c.updated_at = now
        c.version += 1
        self._audit(_CHANGE_ACTION[body.to], principal, "change_request", c, **details)
        self.db.commit()
        return self._change_detail(principal, c, app)
