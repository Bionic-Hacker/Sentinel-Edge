"""Vulnerability management (spec §19, §20; ADR-0021).

Import (`import_scan`, run by `make scan-import` through the CLI):
* One scan run per import. Findings are de-duplicated per application by fingerprint: a finding
  seen again updates its record (last seen, current severity and fix), never a new one.
* A finding that a scan no longer reports is FIXED, but only when that scan included every
  report able to produce it (app.scanning.findings.covered): a scan without DAST cannot fix
  a ZAP finding. A FIXED finding that comes back is reopened, and its SLA clock restarts.
* "Fixed" is never set by hand. A false positive stays a false positive when seen again.
* New and reopened critical or high findings become security events (source `appsec`), so
  they reach security operations; correlation opens an incident for a critical one, except a
  package vulnerability with no fix published (reported, not an incident: nothing to do yet).

SLA (remediation deadline from detection): critical 7 days, high 30, medium 90, low 180.

Risk acceptance (leads only): justification, compensating control and an expiry no further
than the severity allows (critical 30 days, high 90, others 365). The decision is immutable;
it ends when revoked, when it expires (the finding becomes OPEN again) or when the finding is
fixed. At most one acceptance is in force per finding (a partial unique index).

Access: ADMIN, SECURITY_ENGINEER, ANALYST and VIEWER read every application's findings; a
DEVELOPER only those of applications they own (other IDs are "not found", and audited).
Developers move their own findings between open and in progress; leads (ADMIN,
SECURITY_ENGINEER) also mark false positives and accept or revoke risks.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.authz import Principal
from app.core.clock import utcnow
from app.core.errors import ApiError
from app.core.provenance import Provenance
from app.models.application import Application
from app.models.audit import AuditResult
from app.models.security_event import EventCategory, EventSource, Outcome, Severity
from app.models.user import Role
from app.models.vulnerability import (
    ACTIVE_STATUSES,
    AcceptanceEnd,
    FindingCategory,
    RiskAcceptance,
    Sbom,
    ScanRun,
    ScanSource,
    ScanTool,
    Vulnerability,
    VulnStatus,
)
from app.scanning.findings import covered
from app.schemas.vulnerabilities import (
    MAX_SBOM_COMPONENTS,
    AcceptanceOut,
    AppRef,
    ImportedFinding,
    LastScan,
    RevokeAcceptance,
    RiskAcceptanceCreate,
    SbomComponent,
    SbomDetail,
    SbomList,
    SbomSummary,
    ScanList,
    ScanRef,
    ScanReport,
    ScanSummary,
    SeverityCounts,
    StatusChange,
    VulnerabilityDetail,
    VulnerabilityOverview,
    VulnerabilityPage,
    VulnerabilitySummary,
)
from app.services import audit, security_events
from app.services.audit import SYSTEM_CONTEXT, AuditAction, RequestContext
from app.services.security_events import EventContext

SLA: dict[Severity, timedelta | None] = {
    Severity.CRITICAL: timedelta(days=7),
    Severity.HIGH: timedelta(days=30),
    Severity.MEDIUM: timedelta(days=90),
    Severity.LOW: timedelta(days=180),
    Severity.INFO: None,
}
MAX_ACCEPTANCE_DAYS: dict[Severity, int] = {
    Severity.CRITICAL: 30,
    Severity.HIGH: 90,
    Severity.MEDIUM: 365,
    Severity.LOW: 365,
    Severity.INFO: 365,
}
EVENT_SEVERITIES = frozenset({Severity.CRITICAL, Severity.HIGH})
# One import cannot flood the event store: beyond this, one summary event stands for the rest.
MAX_EVENTS_PER_IMPORT = 50
SYSTEM_ACTOR = "system:vulnerability-management"

LEADS = frozenset({Role.ADMIN, Role.SECURITY_ENGINEER})
SEES_ALL = frozenset({Role.ADMIN, Role.SECURITY_ENGINEER, Role.ANALYST, Role.VIEWER})
REMEDIATORS = frozenset({Role.ADMIN, Role.SECURITY_ENGINEER, Role.DEVELOPER})

_EVENT_CATEGORY = {
    FindingCategory.SECRET: EventCategory.EXPOSED_SECRET,
    FindingCategory.SCA: EventCategory.VULNERABLE_DEPENDENCY,
    FindingCategory.CONTAINER: EventCategory.VULNERABLE_DEPENDENCY,
    FindingCategory.SAST: EventCategory.CODE_WEAKNESS,
    FindingCategory.IAC: EventCategory.CODE_WEAKNESS,
    FindingCategory.DAST: EventCategory.CODE_WEAKNESS,
}


class ScanImportError(ValueError):
    """The import cannot proceed (unknown application, malformed SBOM): nothing is stored."""


def sla_due(severity: Severity, start: datetime) -> datetime | None:
    window = SLA[severity]
    return start + window if window else None


def _sla_start(v: Vulnerability) -> datetime:
    """When the SLA clock started: detection, or the last reopening. Derived from the stored
    due date so a severity change can recompute it without another column."""
    window = SLA[v.severity]
    if v.sla_due_at is not None and window is not None:
        return v.sla_due_at - window
    return v.first_seen_at


def is_package_vulnerability(v: Vulnerability) -> bool:
    return v.category in (FindingCategory.SCA, FindingCategory.CONTAINER) and bool(v.cve)


def is_fixable(v: Vulnerability) -> bool:
    return not is_package_vulnerability(v) or bool(v.fixed_version)


def expire_acceptances(db: Session, now: datetime | None = None) -> int:
    """End every acceptance past its expiry and reopen its finding. Idempotent; the caller
    commits. Run on import, on every read of findings and before every change."""
    now = now or utcnow()
    expired = db.scalars(
        select(RiskAcceptance)
        .where(RiskAcceptance.ended_at.is_(None), RiskAcceptance.expires_at <= now)
        .with_for_update(skip_locked=True)
    ).all()
    for acceptance in expired:
        acceptance.ended_at = now
        acceptance.end_reason = AcceptanceEnd.EXPIRED
        acceptance.ended_by_label = SYSTEM_ACTOR
        v = db.get(Vulnerability, acceptance.vulnerability_id)
        if v is not None and v.status is VulnStatus.ACCEPTED_RISK:
            v.status = VulnStatus.OPEN
            v.updated_at = now
            v.version += 1
        audit.record(
            db,
            action=AuditAction.RISK_ACCEPTANCE_EXPIRED,
            result=AuditResult.SUCCESS,
            actor=SYSTEM_ACTOR,
            ctx=SYSTEM_CONTEXT,
            resource_type="vulnerability",
            resource_id=str(acceptance.vulnerability_id),
            details={"acceptance": acceptance.reference, "expired_at": now.isoformat()},
        )
    if expired:
        db.flush()
    return len(expired)


# --- SBOMs --------------------------------------------------------------------------------------


def _licenses(component: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for entry in component.get("licenses") or []:
        if not isinstance(entry, dict):
            continue
        lic = entry.get("license") or {}
        value = entry.get("expression") or lic.get("id") or lic.get("name")
        if value:
            out.append(str(value)[:100])
    return out[:10]


def _clip(value: Any, size: int) -> str | None:
    if value is None or value == "":
        return None
    return "".join(c if c.isprintable() else "?" for c in str(value))[:size]


def parse_sbom(artifact: str, document: Any) -> dict[str, Any]:
    """Validate a CycloneDX JSON document and extract what the UI searches and shows."""
    if not isinstance(document, dict) or document.get("bomFormat") != "CycloneDX":
        raise ScanImportError(f"SBOM {artifact}: not a CycloneDX JSON document")
    spec = str(document.get("specVersion", ""))
    if not spec or len(spec) > 8:
        raise ScanImportError(f"SBOM {artifact}: missing or invalid specVersion")
    raw = document.get("components") or []
    if not isinstance(raw, list):
        raise ScanImportError(f"SBOM {artifact}: components must be a list")
    if len(raw) > MAX_SBOM_COMPONENTS:
        raise ScanImportError(f"SBOM {artifact}: more than {MAX_SBOM_COMPONENTS} components")
    components = [
        {
            "name": _clip(c.get("name"), 300) or "?",
            "version": _clip(c.get("version"), 200),
            "type": _clip(c.get("type"), 40),
            "purl": _clip(c.get("purl"), 500),
            "licenses": _licenses(c),
        }
        for c in raw
        if isinstance(c, dict)
    ]
    subject = (document.get("metadata") or {}).get("component") or {}
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return {
        "spec_version": spec,
        "subject": _clip(subject.get("name"), 300) or artifact,
        "subject_version": _clip(subject.get("version"), 200),
        "components": components,
        "sha256": hashlib.sha256(canonical.encode()).hexdigest(),
    }


# --- Import -------------------------------------------------------------------------------------


@dataclass
class _Counts:
    new: int = 0
    reopened: int = 0
    fixed: int = 0
    unchanged: int = 0


_SCANNER_FIELDS = (
    "rule_id",
    "title",
    "component",
    "location",
    "cve",
    "cvss",
    "fixed_version",
    "recommendation",
)


def _apply_scanner_fields(v: Vulnerability, f: ImportedFinding) -> None:
    for name in _SCANNER_FIELDS:
        setattr(v, name, getattr(f, name))
    v.references = list(f.references)
    if v.severity != f.severity:
        start = _sla_start(v)
        v.severity = f.severity
        v.sla_due_at = sla_due(f.severity, start)


def import_scan(
    db: Session,
    *,
    application_slug: str,
    report: ScanReport,
    sboms: dict[str, Any],
    source: ScanSource,
    commit_sha: str | None,
    branch: str | None,
    actor_label: str,
    now: datetime | None = None,
) -> ScanRun:
    """Store one scan. The caller commits; on any exception nothing is kept."""
    now = now or utcnow()
    app = db.scalar(
        select(Application).where(Application.slug == application_slug).with_for_update()
    )  # also serializes imports for one application
    if app is None:
        raise ScanImportError(f"no application with slug {application_slug!r}")
    parsed_sboms = {name: parse_sbom(name, doc) for name, doc in sorted(sboms.items())}
    expired = expire_acceptances(db, now)

    # Load before anything is pending, then build the import without autoflush: a scan run is
    # insert-only (migration 0009), so it is inserted once, with its final summary.
    existing = {
        v.fingerprint: v
        for v in db.scalars(
            select(Vulnerability).where(Vulnerability.application_id == app.id).with_for_update()
        )
    }
    in_force = {
        a.vulnerability_id: a
        for a in db.scalars(
            select(RiskAcceptance)
            .join(Vulnerability, Vulnerability.id == RiskAcceptance.vulnerability_id)
            .where(Vulnerability.application_id == app.id, RiskAcceptance.ended_at.is_(None))
            .with_for_update(of=RiskAcceptance)
        )
    }
    scan_id = uuid.uuid4()
    counts = _Counts()
    unique: dict[str, ImportedFinding] = {}
    for f in report.findings:
        unique.setdefault(f.fingerprint, f)
    to_report: list[tuple[str, Vulnerability, bool]] = []  # (new|reopened, finding, fixable)
    new_rows: list[Vulnerability] = []

    for f in unique.values():
        v = existing.get(f.fingerprint)
        if v is None:
            v = Vulnerability(
                id=uuid.uuid4(),
                application_id=app.id,
                fingerprint=f.fingerprint,
                tool=f.tool,
                category=f.category,
                severity=f.severity,
                status=VulnStatus.OPEN,
                first_seen_at=now,
                last_seen_at=now,
                first_scan_id=scan_id,
                last_scan_id=scan_id,
                sla_due_at=sla_due(f.severity, now),
                times_reopened=0,
                created_at=now,
                updated_at=now,
                version=1,
            )
            _apply_scanner_fields(v, f)
            new_rows.append(v)
            counts.new += 1
            if f.severity in EVENT_SEVERITIES:
                to_report.append(("new", v, f.fixable))
            continue
        _apply_scanner_fields(v, f)
        v.last_seen_at = now
        v.last_scan_id = scan_id
        v.updated_at = now
        if v.status is VulnStatus.FIXED:
            v.status = VulnStatus.OPEN
            v.resolved_at = None
            v.times_reopened += 1
            v.sla_due_at = sla_due(v.severity, now)
            v.version += 1
            counts.reopened += 1
            if v.severity in EVENT_SEVERITIES:
                to_report.append(("reopened", v, f.fixable))
        else:
            counts.unchanged += 1

    for fingerprint, v in existing.items():
        if fingerprint in unique or v.status not in (*ACTIVE_STATUSES, VulnStatus.ACCEPTED_RISK):
            continue
        if not covered(v.tool, v.category, report.reports):
            continue
        acceptance = in_force.get(v.id)
        if acceptance is not None:
            acceptance.ended_at = now
            acceptance.end_reason = AcceptanceEnd.FIXED
            acceptance.ended_by_label = SYSTEM_ACTOR
        v.status = VulnStatus.FIXED
        v.resolved_at = now
        v.updated_at = now
        v.version += 1
        counts.fixed += 1

    by_severity = Counter(str(f.severity) for f in unique.values())
    scan = ScanRun(
        id=scan_id,
        application_id=app.id,
        source=source,
        commit_sha=commit_sha,
        branch=branch,
        imported_by_label=actor_label,
        imported_at=now,
        generated_at=report.generated_at,
        reports=list(report.reports),
        gate_passed=report.passed,
        summary={
            "total": len(unique),
            "by_severity": {str(s): by_severity.get(str(s), 0) for s in Severity},
            "new": counts.new,
            "reopened": counts.reopened,
            "fixed": counts.fixed,
            "unchanged": counts.unchanged,
            "acceptances_expired": expired,
            "sboms": sorted(parsed_sboms),
            "events": min(len(to_report), MAX_EVENTS_PER_IMPORT),
        },
    )
    # The scan run first (findings reference it), then the findings, then the SBOMs.
    db.add(scan)
    db.flush()
    db.add_all(new_rows)
    db.flush()
    for name, data in parsed_sboms.items():
        db.add(
            Sbom(
                id=uuid.uuid4(),
                scan_id=scan.id,
                application_id=app.id,
                artifact=name,
                format="CycloneDX",
                spec_version=data["spec_version"],
                subject=data["subject"],
                subject_version=data["subject_version"],
                component_count=len(data["components"]),
                components=data["components"],
                document=sboms[name],
                document_sha256=data["sha256"],
                created_at=now,
            )
        )
    db.flush()
    audit.record(
        db,
        action=AuditAction.SCAN_IMPORTED,
        result=AuditResult.SUCCESS,
        actor=actor_label,
        ctx=SYSTEM_CONTEXT,
        resource_type="scan",
        resource_id=str(scan.id),
        details={
            "application": app.slug,
            "scan": scan.reference,
            "source": str(source),
            "commit": commit_sha,
            "gate_passed": report.passed,
            **{k: scan.summary[k] for k in ("total", "new", "reopened", "fixed")},
        },
    )
    _report_events(db, app, scan, to_report, actor_label)
    return scan


def _report_events(
    db: Session,
    app: Application,
    scan: ScanRun,
    to_report: Sequence[tuple[str, Vulnerability, bool]],
    actor_label: str,
) -> None:
    ctx = EventContext(actor_label=actor_label)
    ordered = sorted(to_report, key=lambda item: -item[1].severity.rank)
    for kind, v, fixable in ordered[:MAX_EVENTS_PER_IMPORT]:
        security_events.record_event(
            db,
            source=EventSource.APPSEC,
            category=_EVENT_CATEGORY[v.category],
            severity=v.severity,
            outcome=Outcome.DETECTED,
            title=f"{'New' if kind == 'new' else 'Reopened'} {v.severity} finding: {v.title}",
            ctx=ctx,
            provenance=Provenance.LOCAL,
            rule_id=v.rule_id,
            evidence={
                "vulnerability": v.reference,
                "vulnerability_id": str(v.id),
                "application": app.slug,
                "scan": scan.reference,
                "tool": str(v.tool),
                "component": v.component,
                "location": v.location,
                "cve": v.cve,
                "fixable": fixable,
            },
            # An unfixable package vulnerability is reported but opens no incident.
            correlate=fixable,
        )
    rest = len(ordered) - MAX_EVENTS_PER_IMPORT
    if rest > 0:
        top = ordered[MAX_EVENTS_PER_IMPORT][1].severity
        security_events.record_event(
            db,
            source=EventSource.APPSEC,
            category=EventCategory.VULNERABLE_DEPENDENCY,
            severity=top,
            outcome=Outcome.DETECTED,
            title=f"{rest} more new or reopened critical/high findings in {scan.reference}",
            ctx=ctx,
            provenance=Provenance.LOCAL,
            evidence={"application": app.slug, "scan": scan.reference, "omitted": rest},
            correlate=False,
        )


# --- API ---------------------------------------------------------------------------------------


def _end_of_day(day: date) -> datetime:
    return datetime.combine(day, time(23, 59, 59), tzinfo=UTC)


class VulnerabilityService:
    def __init__(self, *, db: Session, ctx: RequestContext) -> None:
        self.db = db
        self.ctx = ctx

    # --- access -----------------------------------------------------------------------------

    def _visible_apps(self, principal: Principal) -> Any:
        """None for roles that see every application, else a subquery of the caller's own."""
        if principal.user.role in SEES_ALL:
            return None
        return select(Application.id).where(Application.owner_id == principal.user.id)

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

    def _check_app(
        self, principal: Principal, app_id: uuid.UUID, resource_type: str, resource_id: uuid.UUID
    ) -> Application:
        app = self.db.get(Application, app_id)
        assert app is not None  # noqa: S101 - foreign key  # nosec B101
        if principal.user.role in SEES_ALL or app.owner_id == principal.user.id:
            return app
        raise self._deny(principal, resource_type, resource_id)

    def _vulnerability(
        self, principal: Principal, vulnerability_id: uuid.UUID, *, lock: bool = False
    ) -> tuple[Vulnerability, Application]:
        v = self.db.get(Vulnerability, vulnerability_id, with_for_update=lock)
        if v is None:
            raise ApiError(404, "not_found", "Not Found")
        return v, self._check_app(principal, v.application_id, "vulnerability", v.id)

    def _sweep(self) -> None:
        if expire_acceptances(self.db):
            self.db.commit()

    # --- presentation -----------------------------------------------------------------------

    @staticmethod
    def _app_ref(app: Application) -> AppRef:
        return AppRef(id=app.id, slug=app.slug, name=app.name)

    def _scan_ref(self, scan_id: uuid.UUID) -> ScanRef:
        scan = self.db.get(ScanRun, scan_id)
        assert scan is not None  # noqa: S101 - foreign key  # nosec B101
        return ScanRef(id=scan.id, reference=scan.reference, imported_at=scan.imported_at)

    @staticmethod
    def _overdue(v: Vulnerability, now: datetime) -> bool:
        return v.status in ACTIVE_STATUSES and v.sla_due_at is not None and v.sla_due_at < now

    def _summary(self, v: Vulnerability, app: Application, now: datetime) -> VulnerabilitySummary:
        return VulnerabilitySummary(
            id=v.id,
            reference=v.reference,
            application=self._app_ref(app),
            tool=v.tool,
            category=v.category,
            rule_id=v.rule_id,
            title=v.title,
            severity=v.severity,
            component=v.component,
            location=v.location,
            cve=v.cve,
            fixed_version=v.fixed_version,
            fixable=is_fixable(v),
            status=v.status,
            first_seen_at=v.first_seen_at,
            last_seen_at=v.last_seen_at,
            resolved_at=v.resolved_at,
            sla_due_at=v.sla_due_at,
            overdue=self._overdue(v, now),
            times_reopened=v.times_reopened,
            version=v.version,
        )

    @staticmethod
    def _acceptance(a: RiskAcceptance) -> AcceptanceOut:
        return AcceptanceOut(
            id=a.id,
            reference=a.reference,
            justification=a.justification,
            compensating_control=a.compensating_control,
            approver_label=a.approver_label,
            created_at=a.created_at,
            expires_at=a.expires_at,
            ended_at=a.ended_at,
            end_reason=a.end_reason,
            ended_by_label=a.ended_by_label,
            in_force=a.ended_at is None,
        )

    @staticmethod
    def allowed_statuses(principal: Principal, v: Vulnerability) -> list[VulnStatus]:
        role = principal.user.role
        if role not in REMEDIATORS:
            return []
        moves: list[VulnStatus] = []
        if v.status is VulnStatus.OPEN:
            moves.append(VulnStatus.IN_PROGRESS)
        elif v.status is VulnStatus.IN_PROGRESS:
            moves.append(VulnStatus.OPEN)
        if role in LEADS:
            if v.status in ACTIVE_STATUSES:
                moves.append(VulnStatus.FALSE_POSITIVE)
            elif v.status is VulnStatus.FALSE_POSITIVE:
                moves.append(VulnStatus.OPEN)
        return moves

    def _detail(
        self, principal: Principal, v: Vulnerability, app: Application
    ) -> VulnerabilityDetail:
        now = utcnow()
        acceptances = self.db.scalars(
            select(RiskAcceptance)
            .where(RiskAcceptance.vulnerability_id == v.id)
            .order_by(RiskAcceptance.created_at.desc())
        ).all()
        lead = principal.user.role in LEADS
        return VulnerabilityDetail(
            **self._summary(v, app, now).model_dump(),
            cvss=v.cvss,
            recommendation=v.recommendation,
            references=list(v.references),
            status_note=v.status_note,
            first_scan=self._scan_ref(v.first_scan_id),
            last_scan=self._scan_ref(v.last_scan_id),
            acceptances=[self._acceptance(a) for a in acceptances],
            allowed_statuses=self.allowed_statuses(principal, v),
            can_accept_risk=lead and v.status in ACTIVE_STATUSES,
            can_revoke_acceptance=lead and v.status is VulnStatus.ACCEPTED_RISK,
            max_acceptance_days=MAX_ACCEPTANCE_DAYS[v.severity],
        )

    # --- reads ------------------------------------------------------------------------------

    def list_vulnerabilities(
        self,
        principal: Principal,
        *,
        limit: int,
        before: int | None,
        application_id: uuid.UUID | None,
        statuses: Sequence[VulnStatus],
        min_severity: Severity | None,
        category: FindingCategory | None,
        tool: ScanTool | None,
        fixable: bool | None,
        overdue: bool | None,
        search: str | None,
    ) -> VulnerabilityPage:
        """Newest first, keyset-paginated by `number` within the filter."""
        self._sweep()
        now = utcnow()
        query = select(Vulnerability, Application).join(
            Application, Application.id == Vulnerability.application_id
        )
        visible = self._visible_apps(principal)
        if visible is not None:
            query = query.where(Vulnerability.application_id.in_(visible))
        if application_id is not None:
            query = query.where(Vulnerability.application_id == application_id)
        if statuses:
            query = query.where(Vulnerability.status.in_(list(statuses)))
        if min_severity is not None:
            allowed = [s for s in Severity if s.rank >= min_severity.rank]
            query = query.where(Vulnerability.severity.in_(allowed))
        if category is not None:
            query = query.where(Vulnerability.category == category)
        if tool is not None:
            query = query.where(Vulnerability.tool == tool)
        package = Vulnerability.category.in_(
            [FindingCategory.SCA, FindingCategory.CONTAINER]
        ) & Vulnerability.cve.is_not(None)
        if fixable is True:
            query = query.where(~package | Vulnerability.fixed_version.is_not(None))
        elif fixable is False:
            query = query.where(package & Vulnerability.fixed_version.is_(None))
        if overdue is True:
            query = query.where(
                Vulnerability.status.in_(list(ACTIVE_STATUSES)), Vulnerability.sla_due_at < now
            )
        if search:
            escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            like = f"%{escaped}%"
            query = query.where(
                Vulnerability.title.ilike(like, escape="\\")
                | Vulnerability.component.ilike(like, escape="\\")
                | Vulnerability.rule_id.ilike(like, escape="\\")
                | Vulnerability.cve.ilike(like, escape="\\")
            )
        if before is not None:
            query = query.where(Vulnerability.number < before)
        query = query.order_by(Vulnerability.number.desc()).limit(limit + 1)
        rows = list(self.db.execute(query).all())
        has_more = len(rows) > limit
        rows = rows[:limit]
        items = [self._summary(v, app, now) for v, app in rows]
        return VulnerabilityPage(
            items=items, next_before=rows[-1][0].number if has_more and rows else None
        )

    def overview(
        self, principal: Principal, application_id: uuid.UUID | None
    ) -> VulnerabilityOverview:
        self._sweep()
        now = utcnow()
        scope = select(Vulnerability)
        visible = self._visible_apps(principal)
        if visible is not None:
            scope = scope.where(Vulnerability.application_id.in_(visible))
        if application_id is not None:
            scope = scope.where(Vulnerability.application_id == application_id)
        rows = self.db.scalars(scope).all()
        active = [v for v in rows if v.status in ACTIVE_STATUSES]
        counts = Counter(str(v.severity) for v in active)
        since = now - timedelta(days=30)

        last = select(ScanRun).order_by(ScanRun.imported_at.desc()).limit(1)
        if visible is not None:
            last = last.where(ScanRun.application_id.in_(visible))
        if application_id is not None:
            last = last.where(ScanRun.application_id == application_id)
        scan = self.db.scalar(last)
        last_scan = None
        if scan is not None:
            app = self.db.get(Application, scan.application_id)
            assert app is not None  # noqa: S101 - foreign key  # nosec B101
            last_scan = LastScan(
                id=scan.id,
                reference=scan.reference,
                application=self._app_ref(app),
                source=scan.source,
                imported_at=scan.imported_at,
                generated_at=scan.generated_at,
                commit_sha=scan.commit_sha,
                gate_passed=scan.gate_passed,
            )
        return VulnerabilityOverview(
            active=SeverityCounts(**{s: counts.get(s, 0) for s in (str(x) for x in Severity)}),
            active_total=len(active),
            awaiting_fix=sum(1 for v in active if not is_fixable(v)),
            overdue=sum(1 for v in active if self._overdue(v, now)),
            accepted=sum(1 for v in rows if v.status is VulnStatus.ACCEPTED_RISK),
            false_positive=sum(1 for v in rows if v.status is VulnStatus.FALSE_POSITIVE),
            fixed_30d=sum(
                1
                for v in rows
                if v.status is VulnStatus.FIXED and v.resolved_at and v.resolved_at >= since
            ),
            by_category=dict(Counter(str(v.category) for v in active)),
            last_scan=last_scan,
        )

    def get(self, principal: Principal, vulnerability_id: uuid.UUID) -> VulnerabilityDetail:
        self._sweep()
        v, app = self._vulnerability(principal, vulnerability_id)
        return self._detail(principal, v, app)

    # --- writes -----------------------------------------------------------------------------

    def _audit(
        self, action: AuditAction, principal: Principal, v: Vulnerability, **details: Any
    ) -> None:
        audit.record(
            self.db,
            action=action,
            result=AuditResult.SUCCESS,
            actor=principal.user,
            ctx=self.ctx,
            resource_type="vulnerability",
            resource_id=str(v.id),
            details={"vulnerability": v.reference, "severity": str(v.severity), **details},
        )

    def _locked(
        self, principal: Principal, vulnerability_id: uuid.UUID, version: int
    ) -> tuple[Vulnerability, Application]:
        expire_acceptances(self.db)
        v, app = self._vulnerability(principal, vulnerability_id, lock=True)
        if v.version != version:
            raise ApiError(409, "stale_version", "The finding changed since you loaded it.")
        return v, app

    def change_status(
        self, principal: Principal, vulnerability_id: uuid.UUID, body: StatusChange
    ) -> VulnerabilityDetail:
        v, app = self._locked(principal, vulnerability_id, body.version)
        if body.status not in self.allowed_statuses(principal, v):
            raise ApiError(
                409,
                "invalid_transition",
                f"A finding that is {v.status} cannot be moved to {body.status} here. Fixed is "
                "set by a scan; accepted risk by a risk acceptance.",
            )
        needs_note = body.status is VulnStatus.FALSE_POSITIVE or (
            v.status is VulnStatus.FALSE_POSITIVE
        )
        if needs_note and not (body.note and len(body.note) >= 10):
            raise ApiError(
                422, "note_required", "Explain the decision in a note of at least 10 characters."
            )
        before = v.status
        v.status = body.status
        if body.note:
            v.status_note = body.note
        v.updated_at = utcnow()
        v.version += 1
        self._audit(
            AuditAction.VULNERABILITY_STATUS_CHANGED,
            principal,
            v,
            before=str(before),
            after=str(v.status),
            note=body.note,
        )
        self.db.commit()
        return self._detail(principal, v, app)

    def accept_risk(
        self, principal: Principal, vulnerability_id: uuid.UUID, body: RiskAcceptanceCreate
    ) -> VulnerabilityDetail:
        v, app = self._locked(principal, vulnerability_id, body.version)
        if v.status not in ACTIVE_STATUSES:
            raise ApiError(
                409,
                "invalid_transition",
                f"Only an open finding can be accepted (it is {v.status}).",
            )
        now = utcnow()
        expires_at = _end_of_day(body.expires_on)
        limit_days = MAX_ACCEPTANCE_DAYS[v.severity]
        if expires_at <= now:
            raise ApiError(422, "invalid_expiry", "The expiry date must be in the future.")
        if expires_at > now + timedelta(days=limit_days):
            raise ApiError(
                422,
                "invalid_expiry",
                f"A {v.severity} finding can be accepted for at most {limit_days} days.",
            )
        acceptance = RiskAcceptance(
            id=uuid.uuid4(),
            vulnerability_id=v.id,
            justification=body.justification,
            compensating_control=body.compensating_control,
            approver_id=principal.user.id,
            approver_label=principal.user.email,
            created_at=now,
            expires_at=expires_at,
        )
        self.db.add(acceptance)
        v.status = VulnStatus.ACCEPTED_RISK
        v.updated_at = now
        v.version += 1
        self.db.flush()
        self._audit(
            AuditAction.RISK_ACCEPTED,
            principal,
            v,
            acceptance=acceptance.reference,
            expires_at=expires_at.isoformat(),
        )
        self.db.commit()
        return self._detail(principal, v, app)

    def revoke_acceptance(
        self,
        principal: Principal,
        vulnerability_id: uuid.UUID,
        acceptance_id: uuid.UUID,
        body: RevokeAcceptance,
    ) -> VulnerabilityDetail:
        v, app = self._locked(principal, vulnerability_id, body.version)
        acceptance = self.db.get(RiskAcceptance, acceptance_id, with_for_update=True)
        if acceptance is None or acceptance.vulnerability_id != v.id:
            raise ApiError(404, "not_found", "Not Found")
        if acceptance.ended_at is not None:
            raise ApiError(409, "acceptance_ended", "This acceptance is no longer in force.")
        now = utcnow()
        acceptance.ended_at = now
        acceptance.end_reason = AcceptanceEnd.REVOKED
        acceptance.ended_by_label = principal.user.email
        v.status = VulnStatus.OPEN
        v.status_note = body.note
        v.updated_at = now
        v.version += 1
        self._audit(
            AuditAction.RISK_ACCEPTANCE_REVOKED,
            principal,
            v,
            acceptance=acceptance.reference,
            note=body.note,
        )
        self.db.commit()
        return self._detail(principal, v, app)

    # --- scans and SBOMs --------------------------------------------------------------------

    def _scan_summary(self, scan: ScanRun, app: Application) -> ScanSummary:
        return ScanSummary(
            id=scan.id,
            reference=scan.reference,
            application=self._app_ref(app),
            source=scan.source,
            commit_sha=scan.commit_sha,
            branch=scan.branch,
            imported_by_label=scan.imported_by_label,
            imported_at=scan.imported_at,
            generated_at=scan.generated_at,
            reports=list(scan.reports),
            gate_passed=scan.gate_passed,
            summary=dict(scan.summary),
        )

    def list_scans(
        self, principal: Principal, application_id: uuid.UUID | None, limit: int
    ) -> ScanList:
        query = select(ScanRun, Application).join(
            Application, Application.id == ScanRun.application_id
        )
        visible = self._visible_apps(principal)
        if visible is not None:
            query = query.where(ScanRun.application_id.in_(visible))
        if application_id is not None:
            query = query.where(ScanRun.application_id == application_id)
        rows = self.db.execute(query.order_by(ScanRun.number.desc()).limit(limit)).all()
        return ScanList(items=[self._scan_summary(s, a) for s, a in rows])

    def get_scan(self, principal: Principal, scan_id: uuid.UUID) -> ScanSummary:
        scan = self.db.get(ScanRun, scan_id)
        if scan is None:
            raise ApiError(404, "not_found", "Not Found")
        app = self._check_app(principal, scan.application_id, "scan", scan.id)
        return self._scan_summary(scan, app)

    def _sbom_summary(self, sbom: Sbom, app: Application) -> SbomSummary:
        return SbomSummary(
            id=sbom.id,
            application=self._app_ref(app),
            scan=self._scan_ref(sbom.scan_id),
            artifact=sbom.artifact,
            format=sbom.format,
            spec_version=sbom.spec_version,
            subject=sbom.subject,
            subject_version=sbom.subject_version,
            component_count=sbom.component_count,
            document_sha256=sbom.document_sha256,
            created_at=sbom.created_at,
        )

    def list_sboms(
        self, principal: Principal, application_id: uuid.UUID | None, latest_only: bool
    ) -> SbomList:
        # Columns only: the components and the document stay in the database.
        query = select(Sbom.id).join(Application, Application.id == Sbom.application_id)
        visible = self._visible_apps(principal)
        if visible is not None:
            query = query.where(Sbom.application_id.in_(visible))
        if application_id is not None:
            query = query.where(Sbom.application_id == application_id)
        if latest_only:
            newest = (
                select(Sbom.application_id, Sbom.artifact, func.max(Sbom.created_at).label("at"))
                .group_by(Sbom.application_id, Sbom.artifact)
                .subquery()
            )
            query = query.join(
                newest,
                (newest.c.application_id == Sbom.application_id)
                & (newest.c.artifact == Sbom.artifact)
                & (newest.c.at == Sbom.created_at),
            )
        ids = self.db.scalars(
            query.order_by(Sbom.created_at.desc(), Sbom.artifact).limit(100)
        ).all()
        items = []
        for sbom_id in ids:
            sbom = self.db.get(Sbom, sbom_id)
            assert sbom is not None  # noqa: S101 - just selected  # nosec B101
            app = self.db.get(Application, sbom.application_id)
            assert app is not None  # noqa: S101 - foreign key  # nosec B101
            items.append(self._sbom_summary(sbom, app))
        return SbomList(items=items)

    def _sbom(self, principal: Principal, sbom_id: uuid.UUID) -> tuple[Sbom, Application]:
        sbom = self.db.get(Sbom, sbom_id)
        if sbom is None:
            raise ApiError(404, "not_found", "Not Found")
        return sbom, self._check_app(principal, sbom.application_id, "sbom", sbom.id)

    def get_sbom(
        self, principal: Principal, sbom_id: uuid.UUID, search: str | None, limit: int, offset: int
    ) -> SbomDetail:
        sbom, app = self._sbom(principal, sbom_id)
        components = list(sbom.components)
        if search:
            needle = search.lower()
            components = [
                c
                for c in components
                if needle in str(c.get("name", "")).lower()
                or needle in str(c.get("purl") or "").lower()
            ]
        page = components[offset : offset + limit]
        return SbomDetail(
            **self._sbom_summary(sbom, app).model_dump(),
            components=[SbomComponent(**c) for c in page],
            components_total=len(components),
        )

    def sbom_document(self, principal: Principal, sbom_id: uuid.UUID) -> tuple[Sbom, bytes]:
        sbom, _ = self._sbom(principal, sbom_id)
        body = json.dumps(sbom.document, indent=2, ensure_ascii=False).encode()
        return sbom, body
