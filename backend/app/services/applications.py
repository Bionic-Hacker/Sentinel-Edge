"""Protected application inventory (spec §40).

Access: ADMIN, SECURITY_ENGINEER, ANALYST and VIEWER see every application; a DEVELOPER sees
only the applications they own (object-level authorization on the list and on each record:
another application's ID is "not found" and the attempt is audited). ADMIN and
SECURITY_ENGINEER register and edit applications; nobody deletes them (retire instead).
"""

from __future__ import annotations

import uuid
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.api_policy import ENDPOINTS
from app.core.authz import Principal
from app.core.clock import utcnow
from app.core.errors import ApiError
from app.models.application import Application, AppStatus
from app.models.audit import AuditResult
from app.models.incident import OPEN_STATUSES, Incident
from app.models.security_event import SecurityEvent
from app.models.user import Role, User
from app.models.vulnerability import ACTIVE_STATUSES, ScanRun, Vulnerability
from app.schemas.applications import (
    ApplicationCreate,
    ApplicationList,
    ApplicationOut,
    ApplicationUpdate,
    Measure,
)
from app.schemas.incidents import AssigneeList
from app.services import audit
from app.services.audit import AuditAction, RequestContext
from app.services.incidents import LIVE, _person

OWNER_ROLES = frozenset({Role.ADMIN, Role.SECURITY_ENGINEER, Role.DEVELOPER})
SEES_ALL = frozenset({Role.ADMIN, Role.SECURITY_ENGINEER, Role.ANALYST, Role.VIEWER})


def _planned(phase: int, what: str) -> Measure:
    return Measure(status="planned", value=None, note=f"{what} arrives in Phase {phase}.")


NOT_CONNECTED = Measure(
    status="not_connected",
    value=None,
    note="No telemetry connected: SentinelEdge monitors itself today.",
)


class ApplicationService:
    def __init__(self, *, db: Session, ctx: RequestContext) -> None:
        self.db = db
        self.ctx = ctx

    # --- presentation -------------------------------------------------------------------

    def _out(self, app: Application) -> ApplicationOut:
        owner = self.db.get(User, app.owner_id) if app.owner_id else None
        if app.is_platform:
            since = utcnow() - timedelta(hours=24)
            open_incidents = (
                self.db.scalar(
                    select(func.count())
                    .select_from(Incident)
                    .where(Incident.status.in_(OPEN_STATUSES), Incident.provenance.in_(LIVE))
                )
                or 0
            )
            events = (
                self.db.scalar(
                    select(func.count())
                    .select_from(SecurityEvent)
                    .where(SecurityEvent.occurred_at >= since, SecurityEvent.provenance.in_(LIVE))
                )
                or 0
            )
            api_count = Measure(
                status="measured",
                value=len(ENDPOINTS),
                note="Endpoints in the live route table (API Security Center).",
            )
            incidents = Measure(status="measured", value=open_incidents, note="Open, live only.")
            events_24h = Measure(
                status="measured", value=events, note="Live security events, last 24 hours."
            )
        else:
            api_count = incidents = events_24h = NOT_CONNECTED
        return ApplicationOut(
            id=app.id,
            slug=app.slug,
            name=app.name,
            description=app.description,
            owner=_person(owner),
            environment=app.environment,
            criticality=app.criticality,
            domain=app.domain,
            status=app.status,
            is_platform=app.is_platform,
            version=app.version,
            created_at=app.created_at,
            updated_at=app.updated_at,
            api_count=api_count,
            open_incidents=incidents,
            security_events_24h=events_24h,
            waf_status=_planned(5, "AWS WAF in front of the application"),
            certificate_status=_planned(5, "ACM certificate monitoring"),
            security_score=_planned(10, "The explainable posture score"),
            **self._scan_measures(app),
        )

    def _scan_measures(self, app: Application) -> dict[str, Measure]:
        """Last scan and open findings, measured from imported scans (Phase 8)."""
        scan = self.db.scalar(
            select(ScanRun)
            .where(ScanRun.application_id == app.id)
            .order_by(ScanRun.imported_at.desc())
            .limit(1)
        )
        if scan is None:
            none = Measure(
                status="not_connected",
                value=None,
                note="No scan imported yet: `make scan`, then `make scan-import`.",
            )
            return {"last_scan": none, "vulnerability_count": none}
        days = (utcnow() - scan.imported_at).days
        commit = f", commit {scan.commit_sha[:7]}" if scan.commit_sha else ""
        verdict = "passed" if scan.gate_passed else "failed"
        active = (
            self.db.scalar(
                select(func.count())
                .select_from(Vulnerability)
                .where(
                    Vulnerability.application_id == app.id,
                    Vulnerability.status.in_(ACTIVE_STATUSES),
                )
            )
            or 0
        )
        return {
            "last_scan": Measure(
                status="measured",
                value=days,
                note=f"{scan.reference}, {days} days ago{commit}; gate {verdict}.",
            ),
            "vulnerability_count": Measure(
                status="measured", value=active, note="Open or in progress, from imported scans."
            ),
        }

    # --- reads --------------------------------------------------------------------------

    def list_applications(self, principal: Principal) -> ApplicationList:
        query = select(Application).order_by(
            Application.is_platform.desc(), Application.status, Application.name
        )
        if principal.user.role not in SEES_ALL:  # DEVELOPER: own applications only
            query = query.where(Application.owner_id == principal.user.id)
        return ApplicationList(items=[self._out(a) for a in self.db.scalars(query).all()])

    def get(self, principal: Principal, application_id: uuid.UUID) -> ApplicationOut:
        app = self.db.get(Application, application_id)
        if app is not None and (
            principal.user.role in SEES_ALL or app.owner_id == principal.user.id
        ):
            return self._out(app)
        if app is not None:  # exists, but not theirs: same answer as missing, and audited
            audit.record(
                self.db,
                action=AuditAction.ACCESS_DENIED,
                result=AuditResult.DENIED,
                actor=principal.user,
                ctx=self.ctx,
                resource_type="application",
                resource_id=str(application_id),
                details={"reason": "not_owner"},
            )
            self.db.commit()
        raise ApiError(404, "not_found", "Not Found")

    def owners(self) -> AssigneeList:
        """People who can own an application: active admins, security engineers, developers."""
        users = self.db.scalars(
            select(User)
            .where(User.is_active, User.role.in_(sorted(OWNER_ROLES)))
            .order_by(User.display_name)
        ).all()
        return AssigneeList(items=[p for u in users if (p := _person(u)) is not None])

    # --- writes -------------------------------------------------------------------------

    def _owner(self, owner_id: uuid.UUID | None) -> User | None:
        if owner_id is None:
            return None
        owner = self.db.get(User, owner_id)
        if owner is None or not owner.is_active or owner.role not in OWNER_ROLES:
            raise ApiError(
                422,
                "invalid_owner",
                "The owner must be an active administrator, security engineer or developer.",
            )
        return owner

    def _audit(
        self, action: AuditAction, principal: Principal, app: Application, **details: object
    ) -> None:
        audit.record(
            self.db,
            action=action,
            result=AuditResult.SUCCESS,
            actor=principal.user,
            ctx=self.ctx,
            resource_type="application",
            resource_id=str(app.id),
            details={"slug": app.slug, **details},
        )

    def create(self, principal: Principal, body: ApplicationCreate) -> ApplicationOut:
        owner = self._owner(body.owner_id)
        now = utcnow()
        app = Application(
            id=uuid.uuid4(),
            slug=body.slug,
            name=body.name,
            description=body.description,
            owner_id=owner.id if owner else None,
            environment=body.environment,
            criticality=body.criticality,
            domain=body.domain,
            status=AppStatus.ACTIVE,
            is_platform=False,
            created_at=now,
            updated_at=now,
            version=1,
        )
        self.db.add(app)
        try:
            self.db.flush()
        except IntegrityError:
            self.db.rollback()
            raise ApiError(
                409, "slug_in_use", "An application with this slug already exists."
            ) from None
        self._audit(
            AuditAction.APPLICATION_CREATED,
            principal,
            app,
            name=app.name,
            criticality=str(app.criticality),
            owner=owner.email if owner else None,
        )
        self.db.commit()
        return self._out(app)

    def update(
        self, principal: Principal, application_id: uuid.UUID, body: ApplicationUpdate
    ) -> ApplicationOut:
        app = self.db.get(Application, application_id, with_for_update=True)
        if app is None:
            raise ApiError(404, "not_found", "Not Found")
        if app.version != body.version:
            raise ApiError(409, "stale_version", "The application changed since you loaded it.")
        changes = body.model_dump(exclude_none=True, exclude={"version", "clear_owner", "owner_id"})
        if body.clear_owner and body.owner_id is not None:
            raise ApiError(422, "conflicting_owner", "Set an owner or clear it, not both.")
        if body.owner_id is not None:
            changes["owner_id"] = self._owner(body.owner_id).id  # type: ignore[union-attr]
        elif body.clear_owner:
            changes["owner_id"] = None
        if app.is_platform and changes.get("status") is AppStatus.RETIRED:
            raise ApiError(409, "platform_application", "SentinelEdge itself cannot be retired.")
        changed = {k: v for k, v in changes.items() if getattr(app, k) != v}
        if not changed:
            return self._out(app)
        before = {k: str(getattr(app, k)) for k in changed}
        for key, value in changed.items():
            setattr(app, key, value)
        app.version += 1
        app.updated_at = utcnow()
        self._audit(
            AuditAction.APPLICATION_UPDATED,
            principal,
            app,
            before=before,
            after={k: str(v) for k, v in changed.items()},
        )
        self.db.commit()
        return self._out(app)
