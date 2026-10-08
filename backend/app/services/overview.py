"""Security dashboard (spec §12): posture, incidents, threats and traffic for one view.

Sources, all real reads of this platform's data:
* security events and incidents (Phase 7), filtered to one provenance view;
* per-endpoint request counters (Phase 6) for live traffic, which hold no IP addresses;
* simulation run records for simulated traffic;
* the API inventory (Phase 6) and the simulated WAF's rule modes for control status.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import FastAPI
from sqlalchemy import and_, case, func, select
from sqlalchemy.orm import Session

from app.core.clock import utcnow
from app.models.api_metrics import UNMATCHED_ROUTE, ApiEndpointStat
from app.models.incident import (
    OPEN_STATUSES,
    Incident,
    IncidentStatus,
    IncidentTimelineEntry,
    TimelineKind,
)
from app.models.security_event import EventSource, Outcome, SecurityEvent, Severity
from app.models.simulation import SimulationRun, WafMode
from app.schemas.overview import (
    Control,
    CountryCount,
    EndpointCount,
    EventStats,
    IncidentStats,
    Overview,
    RecentIncident,
    RuleCount,
    SeriesPoint,
    Source,
    StatusLine,
    Traffic,
    TrafficPoint,
)
from app.security.http_analysis import RULES as HTTP_RULES
from app.services import correlation
from app.services.api_inventory import build_inventory
from app.services.incidents import view_provenances
from app.services.simulator import waf_modes

E = SecurityEvent
STOPPED = (Outcome.BLOCKED, Outcome.REJECTED, Outcome.THROTTLED)
REACHED = (Outcome.ALLOWED, Outcome.DETECTED)
REQUEST_SENSORS = (EventSource.HTTP_ANALYSIS, EventSource.WAF)
SEVERITY_RANK = {s.value: s.rank for s in Severity}


def _hour(value: datetime) -> datetime:
    return value.astimezone(UTC).replace(minute=0, second=0, microsecond=0)


def _hours(now: datetime, hours: int) -> list[datetime]:
    last = _hour(now)
    return [last - timedelta(hours=h) for h in range(hours - 1, -1, -1)]


def _utc_hour(column: Any) -> Any:
    return func.date_trunc("hour", func.timezone("UTC", column))


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


class OverviewService:
    def __init__(self, *, db: Session, app: FastAPI) -> None:
        self.db = db
        self.app = app

    def build(self, *, view: str, hours: int) -> Overview:
        now = utcnow()
        since = now - timedelta(hours=hours)
        provenances = view_provenances(view)
        in_view = and_(E.occurred_at >= since, E.provenance.in_(provenances))

        events = self._events(in_view)
        incidents, recent = self._incidents(provenances, since)
        traffic = (
            self._live_traffic(now, since, hours)
            if view == "live"
            else self._simulated_traffic(now, since, hours)
        )
        return Overview(
            view="live" if view == "live" else "simulated",
            window_hours=hours,
            generated_at=now,
            status=self._status(incidents, events),
            incidents=incidents,
            recent_incidents=recent,
            events=events,
            series=self._series(in_view, now, hours),
            top_sources=self._sources(in_view),
            top_rules=self._rules(in_view),
            countries=self._countries(in_view),
            traffic=traffic,
            controls=self._controls(view, in_view),
        )

    # --- events -------------------------------------------------------------------------

    def _events(self, in_view: Any) -> EventStats:
        rows = self.db.execute(
            select(E.source, E.category, E.severity, E.outcome, func.count())
            .where(in_view)
            .group_by(E.source, E.category, E.severity, E.outcome)
        ).all()
        total = detections = stopped = reached = 0
        by_category: dict[str, int] = defaultdict(int)
        by_severity: dict[str, int] = defaultdict(int)
        by_outcome: dict[str, int] = defaultdict(int)
        for source, category, severity, outcome, n in rows:
            if source is EventSource.CORRELATION:
                detections += n
                continue
            total += n
            by_category[str(category)] += n
            by_severity[str(severity)] += n
            by_outcome[str(outcome)] += n
            if outcome in STOPPED:
                stopped += n
            if source in REQUEST_SENSORS and outcome in REACHED:
                reached += n
        return EventStats(
            total=total,
            detections=detections,
            stopped=stopped,
            reached_app=reached,
            by_category=dict(sorted(by_category.items(), key=lambda kv: -kv[1])),
            by_severity={s.value: by_severity.get(s.value, 0) for s in Severity},
            by_outcome=dict(by_outcome),
        )

    def _series(self, in_view: Any, now: datetime, hours: int) -> list[SeriesPoint]:
        hour = _utc_hour(E.occurred_at)
        rows = self.db.execute(
            select(
                hour,
                func.count().filter(E.source != EventSource.CORRELATION),
                func.count().filter(E.source == EventSource.CORRELATION),
                func.count().filter(
                    E.source != EventSource.CORRELATION,
                    E.severity.in_([Severity.HIGH, Severity.CRITICAL]),
                ),
            )
            .where(in_view)
            .group_by(hour)
        ).all()
        by_hour = {_as_utc(h): (n, d, hc) for h, n, d, hc in rows}
        return [
            SeriesPoint(
                hour=h,
                events=by_hour.get(h, (0, 0, 0))[0],
                detections=by_hour.get(h, (0, 0, 0))[1],
                high_or_critical=by_hour.get(h, (0, 0, 0))[2],
            )
            for h in _hours(now, hours)
        ]

    def _sources(self, in_view: Any) -> list[Source]:
        rank = case({s.value: s.rank for s in Severity}, value=E.severity)
        rows = self.db.execute(
            select(
                E.source_ip,
                func.count(),
                func.max(rank),
                func.array_agg(func.distinct(E.category)),
                func.max(E.evidence["country"].astext),
                func.max(E.occurred_at),
            )
            .where(in_view, E.source_ip.is_not(None), E.source != EventSource.CORRELATION)
            .group_by(E.source_ip)
            .order_by(func.count().desc(), func.max(E.occurred_at).desc())
            .limit(8)
        ).all()
        severities = list(Severity)
        return [
            Source(
                source_ip=ip,
                events=n,
                max_severity=severities[int(top)],
                categories=sorted(categories)[:6],
                country=country,
                last_seen=last,
            )
            for ip, n, top, categories, country, last in rows
        ]

    def _rules(self, in_view: Any) -> list[RuleCount]:
        rows = self.db.execute(
            select(E.rule_id, func.count())
            .where(in_view, E.rule_id.is_not(None))
            .group_by(E.rule_id)
            .order_by(func.count().desc(), E.rule_id)
            .limit(8)
        ).all()
        return [RuleCount(rule_id=r, events=n) for r, n in rows]

    def _countries(self, in_view: Any) -> list[CountryCount]:
        country = E.evidence["country"].astext
        rows = self.db.execute(
            select(country, func.count())
            .where(in_view, country.is_not(None), E.source != EventSource.CORRELATION)
            .group_by(country)
            .order_by(func.count().desc())
            .limit(8)
        ).all()
        return [CountryCount(country=c, events=n) for c, n in rows]

    # --- incidents ----------------------------------------------------------------------

    def _incidents(
        self, provenances: tuple[Any, ...], since: datetime
    ) -> tuple[IncidentStats, list[RecentIncident]]:
        in_view = Incident.provenance.in_(provenances)
        open_rows = self.db.execute(
            select(Incident.severity, Incident.status, Incident.owner_id.is_(None), func.count())
            .where(in_view, Incident.status.in_(OPEN_STATUSES))
            .group_by(Incident.severity, Incident.status, Incident.owner_id.is_(None))
        ).all()
        by_severity = {s.value: 0 for s in Severity}
        by_status = {s.value: 0 for s in OPEN_STATUSES}
        open_total = unassigned = 0
        for severity, status, no_owner, n in open_rows:
            open_total += n
            by_severity[severity.value] += n
            by_status[status.value] += n
            unassigned += n if no_owner else 0

        closed = self.db.execute(
            select(
                func.count(),
                func.avg(func.extract("epoch", Incident.closed_at - Incident.created_at)),
            ).where(in_view, Incident.status == IncidentStatus.CLOSED, Incident.closed_at >= since)
        ).one()
        first_triage = (
            select(
                IncidentTimelineEntry.incident_id,
                func.min(IncidentTimelineEntry.at).label("at"),
            )
            .where(
                IncidentTimelineEntry.kind == TimelineKind.STATUS_CHANGED,
                IncidentTimelineEntry.to_status == IncidentStatus.TRIAGED,
            )
            .group_by(IncidentTimelineEntry.incident_id)
            .subquery()
        )
        triage = self.db.scalar(
            select(func.avg(func.extract("epoch", first_triage.c.at - Incident.created_at)))
            .join(first_triage, first_triage.c.incident_id == Incident.id)
            .where(in_view, Incident.created_at >= since)
        )
        recent = self.db.scalars(
            select(Incident)
            .where(in_view, Incident.status.in_(OPEN_STATUSES))
            .order_by(Incident.number.desc())
            .limit(5)
        ).all()
        stats = IncidentStats(
            open=open_total,
            unassigned=unassigned,
            by_severity=by_severity,
            by_status=by_status,
            closed_in_window=closed[0] or 0,
            mean_minutes_to_triage=round(float(triage) / 60, 1) if triage is not None else None,
            mean_minutes_to_close=round(float(closed[1]) / 60, 1)
            if closed[1] is not None
            else None,
        )
        return stats, [
            RecentIncident(
                id=i.id,
                reference=i.reference,
                title=i.title,
                severity=i.severity,
                status=i.status,
                detected_at=i.detected_at,
            )
            for i in recent
        ]

    @staticmethod
    def _status(incidents: IncidentStats, events: EventStats) -> StatusLine:
        reasons: list[str] = []
        level = "ok"
        critical = incidents.by_severity.get("critical", 0)
        high = incidents.by_severity.get("high", 0)
        if critical:
            level = "critical"
            reasons.append(f"{critical} open critical incident{'s' if critical > 1 else ''}")
        if high:
            level = "critical" if level == "critical" else "attention"
            reasons.append(f"{high} open high-severity incident{'s' if high > 1 else ''}")
        if incidents.unassigned:
            level = "critical" if level == "critical" else "attention"
            reasons.append(f"{incidents.unassigned} open incident(s) without an owner")
        if events.reached_app:
            level = "critical" if level == "critical" else "attention"
            reasons.append(f"{events.reached_app} attack request(s) were not stopped at that layer")
        if not reasons:
            reasons.append("No open high-severity incidents in this view")
        return StatusLine(level=level, reasons=reasons)

    # --- traffic ------------------------------------------------------------------------

    def _live_traffic(self, now: datetime, since: datetime, hours: int) -> Traffic:
        stat = ApiEndpointStat
        rows = self.db.execute(
            select(
                stat.method,
                stat.route,
                stat.hour,
                stat.requests,
                stat.client_errors,
                stat.server_errors,
                stat.unauthenticated + stat.forbidden + stat.throttled,
            ).where(stat.hour >= _hour(since))
        ).all()
        per_hour: dict[datetime, list[int]] = defaultdict(lambda: [0, 0, 0])
        by_method: dict[str, int] = defaultdict(int)
        by_endpoint: dict[tuple[str, str], int] = defaultdict(int)
        requests = client = server = rejected = unknown = 0
        for method, route, hour, n, c4, c5, rej in rows:
            point = per_hour[_as_utc(hour)]
            point[0] += n
            point[1] += rej
            point[2] += c5
            requests += n
            client += c4
            server += c5
            rejected += rej
            by_method[method] += n
            if route == UNMATCHED_ROUTE:
                unknown += n
            else:
                by_endpoint[(method, route)] += n
        top = sorted(by_endpoint.items(), key=lambda kv: -kv[1])[:6]
        return Traffic(
            source="api_metrics",
            requests=requests,
            allowed=requests - client - server,
            rejected=rejected,
            blocked_at_edge=0,
            errors=server,
            unknown_paths=unknown,
            by_method=dict(by_method),
            series=[
                TrafficPoint(
                    hour=h,
                    requests=per_hour[h][0] if h in per_hour else 0,
                    rejected=per_hour[h][1] if h in per_hour else 0,
                    errors=per_hour[h][2] if h in per_hour else 0,
                )
                for h in _hours(now, hours)
            ],
            top_endpoints=[EndpointCount(method=m, endpoint=r, requests=n) for (m, r), n in top],
        )

    def _simulated_traffic(self, now: datetime, since: datetime, hours: int) -> Traffic:
        runs = self.db.scalars(select(SimulationRun).where(SimulationRun.started_at >= since)).all()
        per_hour: dict[datetime, list[int]] = defaultdict(lambda: [0, 0, 0])
        total = benign = blocked = 0
        for run in runs:
            counts = (run.summary or {}).get("requests", {})
            n = int(counts.get("total", 0))
            b = int(counts.get("blocked_by_waf", 0))
            total += n
            blocked += b
            benign += int(counts.get("benign", 0))
            point = per_hour[_hour(run.started_at)]
            point[0] += n
            point[1] += b
        return Traffic(
            source="simulator",
            requests=total,
            allowed=benign,
            rejected=total - benign - blocked,
            blocked_at_edge=blocked,
            errors=0,
            unknown_paths=0,
            by_method={},
            series=[
                TrafficPoint(
                    hour=h,
                    requests=per_hour[h][0] if h in per_hour else 0,
                    rejected=per_hour[h][1] if h in per_hour else 0,
                    errors=0,
                )
                for h in _hours(now, hours)
            ],
            top_endpoints=[],
        )

    # --- controls -----------------------------------------------------------------------

    def _count(self, *where: Any) -> dict[str, int]:
        rows = self.db.execute(
            select(E.severity, func.count()).where(*where).group_by(E.severity)
        ).all()
        return {severity.value: n for severity, n in rows}

    def _controls(self, view: str, in_view: Any) -> dict[str, Control]:
        detection = Control(
            status="measured",
            summary=(
                f"{len(HTTP_RULES)} HTTP analysis rules (detect-only) and "
                f"{len(correlation.ALL_RULES)} correlation rules"
            ),
            values={"http_rules": len(HTTP_RULES), "correlation_rules": len(correlation.ALL_RULES)},
        )
        if view == "live":
            inventory = build_inventory(self.app, self.app.state.api_metrics).summary
            return {
                "detection": detection,
                "api": Control(
                    status="measured",
                    summary=(
                        f"{inventory.endpoints} endpoints, {inventory.needs_attention} need "
                        "attention (API Security Center)"
                    ),
                    values={
                        "endpoints": inventory.endpoints,
                        "critical": inventory.critical,
                        "needs_attention": inventory.needs_attention,
                        "throttled": inventory.throttled,
                    },
                ),
                "waf": Control(
                    status="planned",
                    summary="AWS WAF arrives in Phase 5; a simulated WAF runs in the simulator",
                    values={},
                ),
                "certificates": Control(
                    status="planned",
                    summary="ACM certificate monitoring arrives in Phase 5",
                    values={},
                ),
                "vulnerabilities": Control(
                    status="planned",
                    summary="Vulnerability management arrives in Phase 8",
                    values={},
                ),
            }
        modes = waf_modes(self.db)
        counts = {m.value: sum(1 for v in modes.values() if v is m) for m in WafMode}
        certificates = self._count(in_view, E.source == EventSource.CERTIFICATE)
        dependencies = self._count(in_view, E.source == EventSource.DEPENDENCY)
        return {
            "detection": detection,
            "waf": Control(
                status="simulated",
                summary=(
                    f"Simulated WAF: {counts['block']} rules blocking, {counts['count']} counting, "
                    f"{counts['off']} off"
                ),
                values=counts,
            ),
            "certificates": Control(
                status="simulated",
                summary=f"{sum(certificates.values())} simulated certificate findings",
                values=certificates,
            ),
            "vulnerabilities": Control(
                status="simulated",
                summary=f"{sum(dependencies.values())} simulated dependency findings",
                values=dependencies,
            ),
        }
