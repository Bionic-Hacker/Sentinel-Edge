"""The explainable security posture score (spec §40; ADR-0022).

Every number traces to something a reviewer can open. Each category starts from coverage, the
share of its catalogue controls that are implemented (0-100), then loses points for live
signals, each listed with the records behind it:
* vulnerability management: active findings past their SLA (critical 10, high 5, medium 2);
* monitoring and response: open live incidents (critical 10, high 5);
* governance: approved high or critical exceptions in force (5 each), and requests waiting
  more than seven days for a decision (2 each);
* DevSecOps: the last imported scan failed the gate (10), or no scan was ever imported (5).
A category whose controls are all still planned scores 0 and says so ("planned"). The overall
score is the mean of every category; `built_scope` is the mean of the measured ones only, so
the roadmap is visible without hiding how much of it is not built yet.

No AI and no weights hidden in a model: the method is this docstring, returned with the score.
"""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.clock import utcnow
from app.core.provenance import Provenance
from app.models.application import Application
from app.models.governance import Control, ControlStatus
from app.models.incident import OPEN_STATUSES, Incident
from app.models.posture import PostureSnapshot
from app.models.risk_governance import ExceptionStatus, RiskLevel, SecurityException
from app.models.security_event import Severity
from app.models.vulnerability import ACTIVE_STATUSES, ScanRun, Vulnerability
from app.schemas.posture import (
    Category,
    CategoryState,
    Factor,
    FactorKind,
    Posture,
    TrendPoint,
)
from app.services.governance import sync_catalogue

# (key, label, control families). Every catalogue family belongs to exactly one category
# (tests/unit/test_posture.py), so a new family cannot silently drop out of the score.
CATEGORIES: tuple[tuple[str, str, frozenset[str]], ...] = (
    ("identity", "Identity and access", frozenset({"ID"})),
    ("application", "Application and API", frozenset({"API", "WEB"})),
    (
        "network",
        "Network, data and cloud",
        frozenset({"NET", "DB", "CNT", "IAM", "IAC", "AWS", "COST"}),
    ),
    ("edge", "Edge and TLS", frozenset({"EDGE", "DNS", "LB"})),
    ("waf", "WAF", frozenset({"WAF"})),
    ("logging", "Logging and audit", frozenset({"LOG", "AUD"})),
    ("monitoring", "Monitoring and response", frozenset({"SO", "MON"})),
    ("vulnerability", "Vulnerability management", frozenset({"VM"})),
    ("devsecops", "DevSecOps", frozenset({"CICD", "SEC"})),
    ("ai", "AI security", frozenset({"AI"})),
    ("governance", "Governance", frozenset({"GOV"})),
)
FINDING_POINTS = {Severity.CRITICAL: 10, Severity.HIGH: 5, Severity.MEDIUM: 2}
INCIDENT_POINTS = {Severity.CRITICAL: 10, Severity.HIGH: 5}
LIVE = (Provenance.LOCAL, Provenance.REAL_AWS)
SNAPSHOT_EVERY = timedelta(hours=24)
SYSTEM_ACTOR = "system:posture"
METHOD = (__doc__ or "").strip()


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _signals(db: Session) -> dict[str, list[Factor]]:
    now = utcnow()
    out: dict[str, list[Factor]] = {}

    platform = select(Application.id).where(Application.is_platform).scalar_subquery()
    overdue = list(
        db.scalars(
            select(Vulnerability).where(
                Vulnerability.application_id == platform,
                Vulnerability.status.in_(ACTIVE_STATUSES),
                Vulnerability.sla_due_at < now,
            )
        )
    )
    findings: list[Factor] = []
    for severity, points in FINDING_POINTS.items():
        hits = [v for v in overdue if v.severity is severity]
        if hits:
            findings.append(
                Factor(
                    kind=FactorKind.SIGNAL,
                    label=f"{_plural(len(hits), f'{severity} finding')} past the SLA",
                    points=-points * len(hits),
                    refs=[v.reference for v in hits[:20]],
                    link="/vulnerabilities?overdue=true",
                )
            )
    out["vulnerability"] = findings

    incidents = list(
        db.scalars(
            select(Incident).where(
                Incident.status.in_(OPEN_STATUSES),
                Incident.provenance.in_(LIVE),
                Incident.severity.in_(list(INCIDENT_POINTS)),
            )
        )
    )
    out["monitoring"] = [
        Factor(
            kind=FactorKind.SIGNAL,
            label=f"{_plural(len(found), f'open {severity} incident')}",
            points=-points * len(found),
            refs=[i.reference for i in found[:20]],
            link="/incidents",
        )
        for severity, points in INCIDENT_POINTS.items()
        if (found := [i for i in incidents if i.severity is severity])
    ]

    exceptions = list(
        db.scalars(
            select(SecurityException).where(
                SecurityException.status.in_([ExceptionStatus.APPROVED, ExceptionStatus.REQUESTED])
            )
        )
    )
    carried = [
        e
        for e in exceptions
        if e.status is ExceptionStatus.APPROVED
        and e.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    ]
    waiting = [
        e
        for e in exceptions
        if e.status is ExceptionStatus.REQUESTED and e.created_at < now - timedelta(days=7)
    ]
    governance: list[Factor] = []
    if carried:
        governance.append(
            Factor(
                kind=FactorKind.SIGNAL,
                label=f"{_plural(len(carried), 'high or critical exception')} in force",
                points=-5 * len(carried),
                refs=[e.reference for e in carried],
                link="/compliance?tab=exceptions",
            )
        )
    if waiting:
        governance.append(
            Factor(
                kind=FactorKind.SIGNAL,
                label=f"{_plural(len(waiting), 'exception request')} waiting over 7 days",
                points=-2 * len(waiting),
                refs=[e.reference for e in waiting],
                link="/compliance?tab=exceptions",
            )
        )
    out["governance"] = governance

    last = db.scalar(
        select(ScanRun)
        .where(ScanRun.application_id == platform)
        .order_by(ScanRun.imported_at.desc())
        .limit(1)
    )
    if last is None:
        out["devsecops"] = [
            Factor(
                kind=FactorKind.SIGNAL,
                label="No scan imported yet",
                points=-5,
                refs=[],
                link="/vulnerabilities",
            )
        ]
    elif not last.gate_passed:
        out["devsecops"] = [
            Factor(
                kind=FactorKind.SIGNAL,
                label=f"The last scan ({last.reference}) failed the gate",
                points=-10,
                refs=[last.reference],
                link="/vulnerabilities",
            )
        ]
    return out


def compute(db: Session) -> tuple[int, int, list[Category]]:
    if sync_catalogue(db):
        db.flush()
    controls = list(db.scalars(select(Control).where(~Control.retired).order_by(Control.ref)))
    signals = _signals(db)
    categories: list[Category] = []
    for key, label, families in CATEGORIES:
        mine = [c for c in controls if c.family in families]
        done = [c for c in mine if c.status is ControlStatus.IMPLEMENTED]
        planned = [c for c in mine if c.status is ControlStatus.PLANNED]
        coverage = round(100 * len(done) / len(mine)) if mine else 0
        factors = [
            Factor(
                kind=FactorKind.COVERAGE,
                label=f"{len(done)} of {len(mine)} controls implemented",
                points=coverage,
                refs=[c.ref for c in planned],  # what would raise it
                link=f"/compliance?tab=controls&families={','.join(sorted(families))}",
            )
        ]
        state = CategoryState.MEASURED if done else CategoryState.PLANNED
        if state is CategoryState.MEASURED:
            factors += signals.get(key, [])
        score = max(0, coverage + sum(f.points for f in factors[1:]))
        categories.append(
            Category(
                key=key,
                label=label,
                score=score,
                state=state,
                implemented=len(done),
                planned=len(planned),
                factors=factors,
            )
        )
    overall = round(sum(c.score for c in categories) / len(categories))
    measured = [c.score for c in categories if c.state is CategoryState.MEASURED]
    built = round(sum(measured) / len(measured)) if measured else 0
    return overall, built, categories


def snapshot(db: Session, taken_by: str) -> PostureSnapshot:
    overall, built, categories = compute(db)
    snap = PostureSnapshot(
        taken_at=utcnow(),
        overall=overall,
        built_scope=built,
        categories={c.key: c.score for c in categories},
        taken_by_label=taken_by,
    )
    db.add(snap)
    db.flush()
    return snap


def posture(db: Session) -> Posture:
    """The score now, with its trend. Takes the day's automatic snapshot if none exists."""
    latest = db.scalar(select(PostureSnapshot).order_by(PostureSnapshot.taken_at.desc()).limit(1))
    if latest is None or latest.taken_at < utcnow() - SNAPSHOT_EVERY:
        snapshot(db, SYSTEM_ACTOR)
        db.commit()
    overall, built, categories = compute(db)
    trend = list(
        db.scalars(select(PostureSnapshot).order_by(PostureSnapshot.taken_at.desc()).limit(30))
    )
    return Posture(
        overall=overall,
        built_scope=built,
        categories=categories,
        method=METHOD,
        trend=[
            TrendPoint(taken_at=s.taken_at, overall=s.overall, built_scope=s.built_scope)
            for s in reversed(trend)
        ],
        computed_at=utcnow(),
    )
