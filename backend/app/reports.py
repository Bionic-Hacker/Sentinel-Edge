"""Security reports for automation (Phase 11): the same figures the dashboard shows, from the
command line, as text for a person or JSON for a pipeline.

    python -m app.cli report security|posture|api-inventory|vulnerabilities|waf|certificates
        [--hours 24] [--format text|json]

Reports only read. They run wherever the API can reach its database (locally:
`make report KIND=security`), never print secrets, and label every figure with where it came
from: live events and simulated ones are never mixed (ADR-0009).
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Callable
from datetime import timedelta
from typing import Any, TextIO

from fastapi import FastAPI
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.clock import utcnow
from app.core.config import Settings
from app.core.provenance import Provenance
from app.models.security_event import EventSource, Outcome, SecurityEvent
from app.models.vulnerability import ACTIVE_STATUSES, Vulnerability
from app.services import aws_edge
from app.services.api_inventory import build_inventory
from app.services.overview import OverviewService
from app.services.posture import posture
from app.services.vulnerabilities import sla_due

Report = dict[str, Any]
KINDS = ("security", "posture", "api-inventory", "vulnerabilities", "waf", "certificates")


def security(db: Session, app: FastAPI, hours: int) -> Report:
    o = OverviewService(db=db, app=app).build(view="live", hours=hours)
    return {
        "window_hours": hours,
        "status": o.status.level,
        "reasons": o.status.reasons,
        "incidents": {
            "open": o.incidents.open,
            "unassigned": o.incidents.unassigned,
            "by_severity": o.incidents.by_severity,
        },
        "events": {
            "total": o.events.total,
            "detections": o.events.detections,
            "stopped": o.events.stopped,
            "reached_app": o.events.reached_app,
            "by_category": o.events.by_category,
        },
        "top_rules": [{"rule": r.rule_id, "events": r.events} for r in o.top_rules[:5]],
        "top_sources": [
            {"ip": s.source_ip, "events": s.events, "max_severity": s.max_severity.value}
            for s in o.top_sources[:5]
        ],
    }


def posture_report(db: Session) -> Report:
    p = posture(db)
    return {
        "overall": p.overall,
        "built_scope": p.built_scope,
        "categories": [
            {"category": c.label, "score": c.score, "state": c.state} for c in p.categories
        ],
    }


def api_inventory(app: FastAPI) -> Report:
    inventory = build_inventory(app, app.state.api_metrics)
    items = inventory.items
    return {
        "endpoints": len(items),
        "by_risk": dict(Counter(i.risk for i in items)),
        "public": sorted(
            f"{i.method} {i.path}" for i in items if i.authentication.startswith("None")
        ),
        "metrics_window_hours": inventory.window_hours,
    }


def vulnerabilities(db: Session) -> Report:
    now = utcnow()
    active = db.scalars(select(Vulnerability).where(Vulnerability.status.in_(ACTIVE_STATUSES)))
    by_severity: Counter[str] = Counter()
    overdue = []
    for v in active:
        by_severity[v.severity.value] += 1
        due = sla_due(v.severity, v.first_seen_at)
        if due is not None and due < now:
            overdue.append({"number": v.number, "severity": v.severity.value, "title": v.title})
    return {
        "active": sum(by_severity.values()),
        "by_severity": dict(by_severity),
        "overdue": overdue,
    }


def waf(db: Session, hours: int) -> Report:
    since = utcnow() - timedelta(hours=hours)
    result: Report = {"window_hours": hours}
    for provenance in (Provenance.REAL_AWS, Provenance.SIMULATED):
        events = list(
            db.scalars(
                select(SecurityEvent).where(
                    SecurityEvent.source == EventSource.WAF,
                    SecurityEvent.provenance == provenance,
                    SecurityEvent.outcome == Outcome.BLOCKED,
                    SecurityEvent.occurred_at >= since,
                )
            )
        )
        result[provenance.value.lower()] = {
            "blocked": len(events),
            "by_rule": dict(Counter(e.rule_id or "?" for e in events).most_common(10)),
            "by_category": dict(Counter(e.category.value for e in events)),
            "top_sources": dict(Counter(e.source_ip or "?" for e in events).most_common(5)),
        }
    return result


def certificates(settings: Settings) -> Report:
    if not settings.certificate_regions:
        return {"connected": False, "note": "no ACM regions configured: runs in AWS only"}
    now = utcnow()
    return {
        "connected": True,
        "certificates": [
            {
                "domain": c.domain,
                "region": c.region,
                "status": c.status,
                "days_left": c.days_left(now),
                "renewal": c.renewal_eligibility,
            }
            for c in aws_edge.certificates(settings, refresh=True)
        ],
    }


def build(kind: str, db: Session, settings: Settings, hours: int) -> Report:
    def app() -> FastAPI:
        from app.main import create_app

        return create_app(settings)

    builders: dict[str, Callable[[], Report]] = {
        "security": lambda: security(db, app(), hours),
        "posture": lambda: posture_report(db),
        "api-inventory": lambda: api_inventory(app()),
        "vulnerabilities": lambda: vulnerabilities(db),
        "waf": lambda: waf(db, hours),
        "certificates": lambda: certificates(settings),
    }
    return {"report": kind, "generated_at": utcnow().isoformat(), **builders[kind]()}


def render_text(report: Report, out: TextIO, indent: int = 0) -> None:
    for key, value in report.items():
        label = " " * indent + key.replace("_", " ")
        if isinstance(value, dict):
            print(f"{label}:", file=out)
            render_text(value, out, indent + 2)
        elif isinstance(value, list):
            print(f"{label}: {len(value)}", file=out)
            for item in value:
                text = (
                    ", ".join(f"{k} {v}" for k, v in item.items())
                    if isinstance(item, dict)
                    else item
                )
                print(f"{' ' * (indent + 2)}- {text}", file=out)
        else:
            print(f"{label}: {value}", file=out)


def emit(report: Report, fmt: str, out: TextIO) -> None:
    if fmt == "json":
        print(json.dumps(report, indent=2, default=str), file=out)
    else:
        render_text(report, out)
