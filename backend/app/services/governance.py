"""Threat modeling and the control catalogue (spec §36, §37; ADR-0022).

Catalogue sync (`sync_catalogue`): `app/governance/catalogue.json` is generated from the
reviewed documents (docs/threat-model.md, docs/security-controls.md) and ships with the API. The
first governance request after a new catalogue arrives loads it into the database, under an
advisory lock so concurrent requests load it once:
* controls and requirements are upserted by reference; one dropped from the documents is
  retired, never deleted;
* SentinelEdge's own threat model (origin `catalogue`) is upserted the same way, with its
  elements, threats and the links between threats, controls and requirements.
The catalogue model is read-only here: it changes through a reviewed pull request to the
documents. Every sync is audited with the catalogue's digest.

Application threat models (origin `app`) are created and edited in the application by leads
(ADMIN, SECURITY_ENGINEER), with optimistic concurrency and an audit record for every change.
ANALYST and VIEWER read every model; a DEVELOPER reads the models of applications they own
(other IDs are "not found", and audited). Every role reads the control catalogue.
"""

from __future__ import annotations

import json
import uuid
from collections import Counter
from collections.abc import Iterable
from functools import cache
from pathlib import Path
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.core.authz import Principal
from app.core.clock import utcnow
from app.core.errors import ApiError
from app.models.application import Application, AppStatus
from app.models.audit import AuditResult
from app.models.governance import (
    ELEMENT_PREFIX,
    PASTA_STAGES,
    Control,
    ControlStatus,
    ElementKind,
    ModelElement,
    ModelMethod,
    ModelOrigin,
    ModelStatus,
    Requirement,
    RequirementThreat,
    Threat,
    ThreatControl,
    ThreatModel,
    ThreatStatus,
)
from app.models.user import Role
from app.schemas.governance import (
    AppRef,
    ControlCounts,
    ControlExtension,
    ControlList,
    ControlOut,
    ElementCreate,
    ElementOut,
    ElementUpdate,
    Evidence,
    ModelPermissions,
    ModelStats,
    RequirementList,
    RequirementOut,
    RiskCell,
    StatusCounts,
    ThreatControlOut,
    ThreatCreate,
    ThreatModelCreate,
    ThreatModelDetail,
    ThreatModelList,
    ThreatModelSummary,
    ThreatModelUpdate,
    ThreatOut,
    ThreatRef,
    ThreatUpdate,
)
from app.services import audit
from app.services.audit import SYSTEM_CONTEXT, AuditAction, RequestContext

CATALOGUE_PATH = Path(__file__).resolve().parent.parent / "governance" / "catalogue.json"
# Separate from the audit chain's lock; always taken first by sync, and sync takes the audit
# lock only after it (through audit.record), so the order is the same everywhere.
_SYNC_LOCK_KEY = 0x5E7E1ED70
SYSTEM_ACTOR = "system:governance"

LEADS = frozenset({Role.ADMIN, Role.SECURITY_ENGINEER})
SEES_ALL = frozenset({Role.ADMIN, Role.SECURITY_ENGINEER, Role.ANALYST, Role.VIEWER})
# Threats still carrying risk: what the matrix, "highest open risk" and posture count.
ACTIVE_RISK = frozenset({ThreatStatus.OPEN, ThreatStatus.PLANNED, ThreatStatus.PARTLY_MITIGATED})
_NOT_APPLICABLE = frozenset({ThreatStatus.CLOSED, ThreatStatus.NOT_EXPOSED})


@cache
def load_catalogue() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(CATALOGUE_PATH.read_text(encoding="utf-8"))
    return data


def _platform(db: Session) -> Application:
    app = db.scalar(select(Application).where(Application.is_platform))
    if app is None:  # seeded by migration 0008
        raise RuntimeError("the platform application is missing")
    return app


def _catalogue_model(db: Session, app: Application) -> ThreatModel | None:
    return db.scalar(
        select(ThreatModel).where(
            ThreatModel.application_id == app.id, ThreatModel.origin == ModelOrigin.CATALOGUE
        )
    )


def sync_catalogue(db: Session, catalogue: dict[str, Any] | None = None) -> bool:
    """Load the catalogue if the database holds a different one. Returns True if it did; the
    caller commits. Idempotent and safe under concurrency (advisory lock, digest re-checked)."""
    cat = catalogue or load_catalogue()
    app = _platform(db)
    current = _catalogue_model(db, app)
    if current is not None and current.catalogue_digest == cat["digest"]:
        return False
    db.execute(select(func.pg_advisory_xact_lock(_SYNC_LOCK_KEY)))
    db.expire_all()
    current = _catalogue_model(db, app)
    if current is not None and current.catalogue_digest == cat["digest"]:
        return False

    now = utcnow()
    controls = _sync_controls(db, cat["controls"], now)
    model = current or ThreatModel(
        id=uuid.uuid4(),
        application_id=app.id,
        name="SentinelEdge",
        method=ModelMethod.STRIDE,
        origin=ModelOrigin.CATALOGUE,
        status=ModelStatus.ACTIVE,
        scope=(
            "SentinelEdge itself: the SPA, the API, its database and its delivery pipeline. "
            "Maintained as code in docs/threat-model.md and changed only by reviewed pull request."
        ),
        pasta={},
        created_by_label=SYSTEM_ACTOR,
        created_at=now,
        version=0,
    )
    model.version_label = cat["model"]["version"]
    model.catalogue_digest = cat["digest"]
    model.updated_at = now
    model.version += 1
    if current is None:
        db.add(model)
    db.flush()
    _sync_elements(db, model, cat["model"]["elements"], now)
    threats = _sync_threats(db, model, cat["model"]["threats"], controls, now)
    _sync_requirements(db, cat["requirements"], threats)
    audit.record(
        db,
        action=AuditAction.GOVERNANCE_CATALOGUE_SYNCED,
        result=AuditResult.SUCCESS,
        actor=SYSTEM_ACTOR,
        ctx=SYSTEM_CONTEXT,
        resource_type="threat_model",
        resource_id=str(model.id),
        details={
            "digest": cat["digest"],
            "threat_model_version": cat["model"]["version"],
            "threats": len(cat["model"]["threats"]),
            "controls": len(cat["controls"]),
            "requirements": len(cat["requirements"]),
        },
    )
    db.flush()
    return True


def _sync_controls(db: Session, items: list[dict[str, Any]], now: Any) -> dict[str, Control]:
    existing = {c.ref: c for c in db.scalars(select(Control))}
    wanted = {item["ref"] for item in items}
    for item in items:
        c = existing.get(item["ref"])
        if c is None:
            c = Control(id=uuid.uuid4(), ref=item["ref"])
            db.add(c)
            existing[c.ref] = c
        c.family = item["family"]
        c.layer = item["layer"]
        c.title = item["title"]
        c.status = ControlStatus(item["status"])
        c.phase = item["phase"]
        c.implementation = item["implementation"]
        c.evidence = item["evidence"]
        c.evidence_text = item["evidence_text"]
        c.extensions = item["extensions"]
        c.retired = False
        c.synced_at = now
    for ref, c in existing.items():
        if ref not in wanted and not c.retired:
            c.retired = True
            c.synced_at = now
    db.flush()
    return existing


def _sync_elements(db: Session, model: ThreatModel, items: list[dict[str, Any]], now: Any) -> None:
    existing = {
        (e.kind, e.ref): e
        for e in db.scalars(select(ModelElement).where(ModelElement.model_id == model.id))
    }
    wanted = set()
    for item in items:
        key = (ElementKind(item["kind"]), item["ref"])
        wanted.add(key)
        e = existing.get(key)
        if e is None:
            e = ModelElement(
                id=uuid.uuid4(), model_id=model.id, kind=key[0], ref=key[1], created_at=now
            )
            db.add(e)
        e.name = item["name"][:300]
        e.description = item["description"]
        e.attributes = item["attributes"]
        e.retired = False
        e.updated_at = now
    for key, e in existing.items():
        if key not in wanted and not e.retired:
            e.retired = True
            e.updated_at = now


def _sync_threats(
    db: Session,
    model: ThreatModel,
    items: list[dict[str, Any]],
    controls: dict[str, Control],
    now: Any,
) -> dict[str, Threat]:
    existing = {t.ref: t for t in db.scalars(select(Threat).where(Threat.model_id == model.id))}
    wanted = {item["ref"] for item in items}
    for item in items:
        t = existing.get(item["ref"])
        if t is None:
            t = Threat(
                id=uuid.uuid4(), model_id=model.id, ref=item["ref"], created_at=now, version=0
            )
            db.add(t)
            existing[t.ref] = t
        t.title = item["title"]
        t.stride = item["stride"]
        t.owasp = item["owasp"]
        t.group_name = item["group"]
        t.boundaries = item["boundaries"]
        t.likelihood = item["likelihood"]
        t.impact = item["impact"]
        t.mitigation = item["mitigation"]
        t.status = ThreatStatus(item["status"])
        t.status_text = item["status_text"]
        t.phases = item["phases"]
        t.retired = False
        t.updated_at = now
        t.version += 1
    for ref, t in existing.items():
        if ref not in wanted and not t.retired:
            t.retired = True
            t.updated_at = now
            t.version += 1
    db.flush()
    ids = [t.id for t in existing.values()]
    db.execute(delete(ThreatControl).where(ThreatControl.threat_id.in_(ids)))
    for item in items:
        for ref in item["controls"]:
            db.add(ThreatControl(threat_id=existing[item["ref"]].id, control_id=controls[ref].id))
    db.flush()
    return existing


def _sync_requirements(
    db: Session, items: list[dict[str, Any]], threats: dict[str, Threat]
) -> None:
    existing = {r.ref: r for r in db.scalars(select(Requirement))}
    wanted = {item["ref"] for item in items}
    for position, item in enumerate(items):
        r = existing.get(item["ref"])
        if r is None:
            r = Requirement(id=uuid.uuid4(), ref=item["ref"])
            db.add(r)
            existing[r.ref] = r
        r.title = item["title"]
        r.control_text = item["control_text"]
        r.implementation = item["implementation"]
        r.evidence = item["evidence"]
        r.evidence_text = item["evidence_text"]
        r.phase_text = item["phase_text"]
        r.position = position
        r.retired = False
    for ref, r in existing.items():
        if ref not in wanted:
            r.retired = True
    db.flush()
    db.execute(delete(RequirementThreat))
    for item in items:
        for ref in item["threats"]:
            db.add(
                RequirementThreat(
                    requirement_id=existing[item["ref"]].id, threat_id=threats[ref].id
                )
            )
    db.flush()


# --- API ---------------------------------------------------------------------------------------


def _status_counts(threats: Iterable[Threat]) -> StatusCounts:
    counts = Counter(str(t.status) for t in threats)
    return StatusCounts(**counts)


class GovernanceService:
    def __init__(self, *, db: Session, ctx: RequestContext) -> None:
        self.db = db
        self.ctx = ctx

    def _ensure_catalogue(self) -> None:
        if sync_catalogue(self.db):
            self.db.commit()

    # --- access -----------------------------------------------------------------------------

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

    def _model(
        self, principal: Principal, model_id: uuid.UUID, *, lock: bool = False
    ) -> tuple[ThreatModel, Application]:
        model = self.db.get(ThreatModel, model_id, with_for_update=lock)
        if model is None:
            raise ApiError(404, "not_found", "Not Found")
        app = self.db.get(Application, model.application_id)
        assert app is not None  # noqa: S101 - foreign key  # nosec B101
        if principal.user.role in SEES_ALL or app.owner_id == principal.user.id:
            return model, app
        raise self._deny(principal, "threat_model", model.id)

    def _editable(
        self, principal: Principal, model_id: uuid.UUID
    ) -> tuple[ThreatModel, Application]:
        self._ensure_catalogue()
        model, app = self._model(principal, model_id, lock=True)
        if model.origin is ModelOrigin.CATALOGUE:
            raise ApiError(
                409,
                "maintained_as_code",
                "SentinelEdge's own threat model is maintained as code in docs/threat-model.md "
                "and changes only through a reviewed pull request.",
            )
        return model, app

    # --- catalogue --------------------------------------------------------------------------

    def _catalogue_threat_refs(self) -> dict[uuid.UUID, list[str]]:
        model = _catalogue_model(self.db, _platform(self.db))
        rows = self.db.execute(
            select(ThreatControl.control_id, Threat.ref)
            .join(Threat, Threat.id == ThreatControl.threat_id)
            .where(Threat.model_id == (model.id if model else None), ~Threat.retired)
            .order_by(Threat.ref)
        )
        out: dict[uuid.UUID, list[str]] = {}
        for control_id, ref in rows:
            out.setdefault(control_id, []).append(ref)
        return out

    def list_controls(
        self,
        status: ControlStatus | None = None,
        family: str | None = None,
        search: str | None = None,
    ) -> ControlList:
        self._ensure_catalogue()
        controls = list(
            self.db.scalars(select(Control).where(~Control.retired).order_by(Control.ref))
        )
        cited = self._catalogue_threat_refs()
        counts = ControlCounts(
            implemented=sum(c.status is ControlStatus.IMPLEMENTED for c in controls),
            planned=sum(c.status is ControlStatus.PLANNED for c in controls),
            with_evidence=sum(bool(c.evidence) for c in controls),
        )
        needle = search.lower() if search else None
        items = [
            self._control_out(c, cited.get(c.id, []))
            for c in controls
            if (status is None or c.status is status)
            and (family is None or c.family == family)
            and (
                needle is None
                or needle in c.ref.lower()
                or needle in c.title.lower()
                or needle in c.implementation.lower()
            )
        ]
        return ControlList(items=items, counts=counts, catalogue_digest=load_catalogue()["digest"])

    @staticmethod
    def _control_out(c: Control, threats: list[str]) -> ControlOut:
        return ControlOut(
            ref=c.ref,
            title=c.title,
            family=c.family,
            layer=c.layer,
            status=c.status,
            phase=c.phase,
            implementation=c.implementation,
            evidence=[Evidence(**e) for e in c.evidence],
            evidence_text=c.evidence_text,
            extensions=[
                ControlExtension(
                    phase=x["phase"],
                    title=x["title"],
                    implementation=x["implementation"],
                    evidence=[Evidence(**e) for e in x["evidence"]],
                    evidence_text=x["evidence_text"],
                )
                for x in c.extensions
            ],
            threats=threats,
        )

    def list_requirements(self) -> RequirementList:
        self._ensure_catalogue()
        requirements = list(
            self.db.scalars(
                select(Requirement).where(~Requirement.retired).order_by(Requirement.position)
            )
        )
        links = self.db.execute(
            select(RequirementThreat.requirement_id, Threat)
            .join(Threat, Threat.id == RequirementThreat.threat_id)
            .order_by(Threat.ref)
        ).all()
        by_req: dict[uuid.UUID, list[Threat]] = {}
        for req_id, threat in links:
            by_req.setdefault(req_id, []).append(threat)
        control_refs = self._control_refs([t.id for _, t in links])
        items = []
        for r in requirements:
            threats = by_req.get(r.id, [])
            refs = sorted({ref for t in threats for ref in control_refs.get(t.id, [])})
            items.append(
                RequirementOut(
                    ref=r.ref,
                    title=r.title,
                    threats=[
                        ThreatRef(ref=t.ref, title=t.title, status=t.status, risk=t.risk)
                        for t in threats
                    ],
                    controls=refs,
                    control_text=r.control_text,
                    implementation=r.implementation,
                    evidence=[Evidence(**e) for e in r.evidence],
                    evidence_text=r.evidence_text,
                    phase_text=r.phase_text,
                )
            )
        return RequirementList(items=items)

    def _control_refs(self, threat_ids: list[uuid.UUID]) -> dict[uuid.UUID, list[str]]:
        if not threat_ids:
            return {}
        out: dict[uuid.UUID, list[str]] = {}
        for threat_id, ref in self.db.execute(
            select(ThreatControl.threat_id, Control.ref)
            .join(Control, Control.id == ThreatControl.control_id)
            .where(ThreatControl.threat_id.in_(threat_ids))
            .order_by(Control.ref)
        ):
            out.setdefault(threat_id, []).append(ref)
        return out

    # --- threat models ----------------------------------------------------------------------

    @staticmethod
    def _app_ref(app: Application) -> AppRef:
        return AppRef(id=app.id, slug=app.slug, name=app.name)

    def list_models(
        self, principal: Principal, application_id: uuid.UUID | None = None
    ) -> ThreatModelList:
        self._ensure_catalogue()
        query = (
            select(ThreatModel, Application)
            .join(Application, Application.id == ThreatModel.application_id)
            .order_by(ThreatModel.number)
        )
        if principal.user.role not in SEES_ALL:
            query = query.where(Application.owner_id == principal.user.id)
        if application_id is not None:
            query = query.where(ThreatModel.application_id == application_id)
        rows = self.db.execute(query).all()
        threats: dict[uuid.UUID, list[Threat]] = {}
        if rows:
            for t in self.db.scalars(
                select(Threat).where(Threat.model_id.in_([m.id for m, _ in rows]), ~Threat.retired)
            ):
                threats.setdefault(t.model_id, []).append(t)
        items = []
        for model, app in rows:
            mine = threats.get(model.id, [])
            items.append(
                ThreatModelSummary(
                    id=model.id,
                    reference=model.reference,
                    name=model.name,
                    application=self._app_ref(app),
                    method=model.method,
                    origin=model.origin,
                    status=model.status,
                    version_label=model.version_label,
                    threat_count=len(mine),
                    by_status=_status_counts(mine),
                    highest_open_risk=max(
                        (t.risk for t in mine if t.status in ACTIVE_RISK), default=0
                    ),
                    updated_at=model.updated_at,
                    version=model.version,
                )
            )
        return ThreatModelList(items=items)

    def get_model(self, principal: Principal, model_id: uuid.UUID) -> ThreatModelDetail:
        self._ensure_catalogue()
        model, app = self._model(principal, model_id)
        return self._detail(principal, model, app)

    def _detail(
        self, principal: Principal, model: ThreatModel, app: Application
    ) -> ThreatModelDetail:
        elements = list(
            self.db.scalars(
                select(ModelElement)
                .where(ModelElement.model_id == model.id)
                .order_by(ModelElement.kind, ModelElement.created_at, ModelElement.ref)
            )
        )
        threats = list(
            self.db.scalars(
                select(Threat)
                .where(Threat.model_id == model.id)
                .order_by(Threat.created_at, Threat.ref)
            )
        )
        links: dict[uuid.UUID, list[Control]] = {}
        if threats:
            for threat_id, control in self.db.execute(
                select(ThreatControl.threat_id, Control)
                .join(Control, Control.id == ThreatControl.control_id)
                .where(ThreatControl.threat_id.in_([t.id for t in threats]))
                .order_by(Control.ref)
            ):
                links.setdefault(threat_id, []).append(control)
        catalogue = model.origin is ModelOrigin.CATALOGUE
        return ThreatModelDetail(
            id=model.id,
            reference=model.reference,
            name=model.name,
            application=self._app_ref(app),
            method=model.method,
            origin=model.origin,
            status=model.status,
            scope=model.scope,
            version_label=model.version_label,
            pasta={stage: model.pasta.get(stage, "") for stage in PASTA_STAGES}
            if model.method is ModelMethod.PASTA
            else {},
            elements=[
                ElementOut(
                    id=e.id,
                    kind=e.kind,
                    ref=e.ref,
                    name=e.name,
                    description=e.description,
                    boundaries=list(e.attributes.get("boundaries", [])),
                    threats=list(e.attributes.get("threats", [])),
                    retired=e.retired,
                )
                for e in elements
            ],
            threats=[self._threat_out(t, links.get(t.id, [])) for t in threats],
            stats=self._stats([t for t in threats if not t.retired], links),
            permissions=ModelPermissions(
                can_edit=not catalogue and principal.user.role in LEADS,
                maintained_as_code=catalogue,
            ),
            created_by_label=model.created_by_label,
            created_at=model.created_at,
            updated_at=model.updated_at,
            version=model.version,
        )

    @staticmethod
    def _threat_out(t: Threat, controls: list[Control]) -> ThreatOut:
        return ThreatOut(
            id=t.id,
            ref=t.ref,
            title=t.title,
            stride=t.stride,
            owasp=t.owasp,
            group=t.group_name,
            boundaries=list(t.boundaries),
            likelihood=t.likelihood,
            impact=t.impact,
            risk=t.risk,
            mitigation=t.mitigation,
            status=t.status,
            status_text=t.status_text,
            phases=list(t.phases),
            controls=[
                ThreatControlOut(ref=c.ref, title=c.title, status=c.status, phase=c.phase)
                for c in controls
            ],
            retired=t.retired,
            version=t.version,
        )

    @staticmethod
    def _stats(threats: list[Threat], links: dict[uuid.UUID, list[Control]]) -> ModelStats:
        by_stride: Counter[str] = Counter()
        for t in threats:
            if t.stride.startswith("LLM"):
                by_stride["LLM"] += 1
            else:
                by_stride.update(t.stride.split("/"))
        open_threats = [t for t in threats if t.status in ACTIVE_RISK]
        cells = Counter((t.likelihood, t.impact) for t in open_threats)
        applicable = [t for t in threats if t.status not in _NOT_APPLICABLE]
        return ModelStats(
            by_status=_status_counts(threats),
            by_stride=dict(sorted(by_stride.items())),
            matrix=[
                RiskCell(likelihood=li, impact=im, count=cells.get((li, im), 0))
                for li in (3, 2, 1)
                for im in (1, 2, 3)
            ],
            unmapped=[t.ref for t in applicable if not links.get(t.id)],
            only_planned_controls=[
                t.ref
                for t in applicable
                if links.get(t.id) and all(c.status is ControlStatus.PLANNED for c in links[t.id])
            ],
        )

    # --- writes -----------------------------------------------------------------------------

    def _audit(
        self, action: AuditAction, principal: Principal, model: ThreatModel, **details: Any
    ) -> None:
        audit.record(
            self.db,
            action=action,
            result=AuditResult.SUCCESS,
            actor=principal.user,
            ctx=self.ctx,
            resource_type="threat_model",
            resource_id=str(model.id),
            details={"model": model.reference, **details},
        )

    def _touch(self, model: ThreatModel) -> None:
        model.updated_at = utcnow()
        model.version += 1

    def create_model(self, principal: Principal, body: ThreatModelCreate) -> ThreatModelDetail:
        self._ensure_catalogue()
        app = self.db.get(Application, body.application_id)
        if app is None:
            raise ApiError(422, "unknown_application", "No such application.")
        if app.status is not AppStatus.ACTIVE:
            raise ApiError(409, "application_retired", "The application is retired.")
        now = utcnow()
        model = ThreatModel(
            id=uuid.uuid4(),
            application_id=app.id,
            name=body.name,
            method=body.method,
            origin=ModelOrigin.APP,
            status=ModelStatus.DRAFT,
            scope=body.scope,
            version_label="1",
            pasta={},
            catalogue_digest=None,
            created_by_label=principal.user.email,
            created_at=now,
            updated_at=now,
            version=1,
        )
        self.db.add(model)
        self.db.flush()
        self._audit(
            AuditAction.THREAT_MODEL_CREATED,
            principal,
            model,
            application=app.slug,
            method=str(body.method),
        )
        self.db.commit()
        return self._detail(principal, model, app)

    def update_model(
        self, principal: Principal, model_id: uuid.UUID, body: ThreatModelUpdate
    ) -> ThreatModelDetail:
        model, app = self._editable(principal, model_id)
        if model.version != body.version:
            raise ApiError(409, "stale_version", "The threat model changed since you loaded it.")
        changes: dict[str, Any] = {}
        if body.name is not None and body.name != model.name:
            changes["name"] = [model.name, body.name]
            model.name = body.name
        if body.scope is not None and body.scope != model.scope:
            changes["scope"] = "changed"
            model.scope = body.scope
        if body.status is not None and body.status is not model.status:
            changes["status"] = [str(model.status), str(body.status)]
            model.status = body.status
        if body.pasta is not None:
            if model.method is not ModelMethod.PASTA:
                raise ApiError(422, "not_pasta", "PASTA stages apply only to a PASTA model.")
            merged = {**model.pasta, **body.pasta}
            if merged != model.pasta:
                changes["pasta"] = sorted(
                    k for k in body.pasta if model.pasta.get(k) != body.pasta[k]
                )
                model.pasta = merged
        if changes:
            self._touch(model)
            self._audit(AuditAction.THREAT_MODEL_UPDATED, principal, model, changes=changes)
            self.db.commit()
        return self._detail(principal, model, app)

    def _boundaries(self, model: ThreatModel, refs: list[str]) -> list[str]:
        known = set(
            self.db.scalars(
                select(ModelElement.ref).where(
                    ModelElement.model_id == model.id,
                    ModelElement.kind == ElementKind.BOUNDARY,
                    ~ModelElement.retired,
                )
            )
        )
        if unknown := sorted(set(refs) - known):
            raise ApiError(
                422,
                "unknown_boundary",
                f"No such trust boundary in this model: {', '.join(unknown)}",
            )
        return sorted(set(refs), key=lambda r: int(r[2:]))

    def _next_ref(self, model: ThreatModel, kind: ElementKind) -> str:
        count = self.db.scalar(
            select(func.count())
            .select_from(ModelElement)
            .where(ModelElement.model_id == model.id, ModelElement.kind == kind)
        )
        return f"{ELEMENT_PREFIX[kind]}{(count or 0) + 1}"

    def add_element(
        self, principal: Principal, model_id: uuid.UUID, body: ElementCreate
    ) -> ThreatModelDetail:
        model, app = self._editable(principal, model_id)
        attributes: dict[str, Any] = {}
        if body.kind is ElementKind.FLOW:
            attributes["boundaries"] = self._boundaries(model, body.boundaries)
        elif body.boundaries:
            raise ApiError(
                422, "boundaries_not_allowed", "Only a data flow crosses trust boundaries."
            )
        now = utcnow()
        element = ModelElement(
            id=uuid.uuid4(),
            model_id=model.id,
            kind=body.kind,
            ref=self._next_ref(model, body.kind),
            name=body.name,
            description=body.description,
            attributes=attributes,
            retired=False,
            created_at=now,
            updated_at=now,
        )
        self.db.add(element)
        self._touch(model)
        self._audit(
            AuditAction.THREAT_MODEL_ELEMENT_ADDED,
            principal,
            model,
            kind=str(body.kind),
            ref=element.ref,
        )
        self.db.commit()
        return self._detail(principal, model, app)

    def update_element(
        self, principal: Principal, model_id: uuid.UUID, element_id: uuid.UUID, body: ElementUpdate
    ) -> ThreatModelDetail:
        model, app = self._editable(principal, model_id)
        element = self.db.get(ModelElement, element_id)
        if element is None or element.model_id != model.id:
            raise ApiError(404, "not_found", "Not Found")
        changes: dict[str, Any] = {}
        for field in ("name", "description", "retired"):
            value = getattr(body, field)
            if value is not None and value != getattr(element, field):
                changes[field] = value if field != "description" else "changed"
                setattr(element, field, value)
        if changes:
            element.updated_at = utcnow()
            self._touch(model)
            self._audit(
                AuditAction.THREAT_MODEL_ELEMENT_UPDATED,
                principal,
                model,
                ref=element.ref,
                changes=changes,
            )
            self.db.commit()
        return self._detail(principal, model, app)

    def _controls(self, refs: list[str]) -> list[Control]:
        wanted = sorted(set(refs))
        found = list(
            self.db.scalars(select(Control).where(Control.ref.in_(wanted), ~Control.retired))
        )
        if missing := sorted(set(wanted) - {c.ref for c in found}):
            raise ApiError(422, "unknown_control", f"No such control: {', '.join(missing)}")
        return sorted(found, key=lambda c: c.ref)

    def _link(self, threat: Threat, controls: list[Control]) -> None:
        self.db.execute(delete(ThreatControl).where(ThreatControl.threat_id == threat.id))
        for c in controls:
            self.db.add(ThreatControl(threat_id=threat.id, control_id=c.id))

    def add_threat(
        self, principal: Principal, model_id: uuid.UUID, body: ThreatCreate
    ) -> ThreatModelDetail:
        model, app = self._editable(principal, model_id)
        boundaries = self._boundaries(model, body.boundaries)
        controls = self._controls(body.controls)
        count = self.db.scalar(
            select(func.count()).select_from(Threat).where(Threat.model_id == model.id)
        )
        now = utcnow()
        threat = Threat(
            id=uuid.uuid4(),
            model_id=model.id,
            ref=f"TH-{(count or 0) + 1:03d}",
            title=body.title,
            stride=body.stride,
            owasp=body.owasp,
            group_name="",
            boundaries=boundaries,
            likelihood=body.likelihood,
            impact=body.impact,
            mitigation=body.mitigation,
            status=body.status,
            status_text="",
            phases=[],
            retired=False,
            created_at=now,
            updated_at=now,
            version=1,
        )
        self.db.add(threat)
        self.db.flush()
        self._link(threat, controls)
        self._touch(model)
        self._audit(
            AuditAction.THREAT_ADDED,
            principal,
            model,
            threat=threat.ref,
            risk=threat.risk,
            status=str(threat.status),
            controls=[c.ref for c in controls],
        )
        self.db.commit()
        return self._detail(principal, model, app)

    def update_threat(
        self, principal: Principal, model_id: uuid.UUID, threat_id: uuid.UUID, body: ThreatUpdate
    ) -> ThreatModelDetail:
        model, app = self._editable(principal, model_id)
        threat = self.db.get(Threat, threat_id, with_for_update=True)
        if threat is None or threat.model_id != model.id:
            raise ApiError(404, "not_found", "Not Found")
        if threat.version != body.version:
            raise ApiError(409, "stale_version", "The threat changed since you loaded it.")
        changes: dict[str, Any] = {}
        for field in ("title", "stride", "owasp", "likelihood", "impact", "status", "retired"):
            value = getattr(body, field)
            if value is not None and value != getattr(threat, field):
                changes[field] = [str(getattr(threat, field)), str(value)]
                setattr(threat, field, value)
        if body.mitigation is not None and body.mitigation != threat.mitigation:
            changes["mitigation"] = "changed"
            threat.mitigation = body.mitigation
        if body.boundaries is not None:
            boundaries = self._boundaries(model, body.boundaries)
            if boundaries != threat.boundaries:
                changes["boundaries"] = [threat.boundaries, boundaries]
                threat.boundaries = boundaries
        if body.controls is not None:
            controls = self._controls(body.controls)
            before = sorted(self._control_refs([threat.id]).get(threat.id, []))
            after = [c.ref for c in controls]
            if before != after:
                changes["controls"] = [before, after]
                self._link(threat, controls)
        if changes:
            threat.updated_at = utcnow()
            threat.version += 1
            self._touch(model)
            self._audit(
                AuditAction.THREAT_UPDATED,
                principal,
                model,
                threat=threat.ref,
                changes=changes,
            )
            self.db.commit()
        return self._detail(principal, model, app)
