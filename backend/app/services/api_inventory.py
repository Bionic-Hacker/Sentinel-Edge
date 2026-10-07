"""API Security Center: endpoint inventory with controls, live metrics and status (spec §14).

Three sources, joined per endpoint:
  * the live route table: method, path, and the authentication/authorization guards the
    route actually depends on (the code that enforces them, not a description of it);
  * the policy registry (app.core.api_policy): risk, rate limit, OWASP exposure, data;
  * the hourly metrics table: requests, errors and security rejections in the last 24 hours.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from fastapi import FastAPI
from fastapi.routing import APIRoute, iter_route_contexts

from app.core.api_metrics import ApiMetrics
from app.core.api_policy import ENDPOINTS, Risk
from app.core.authz import authenticated_setup, public_endpoint
from app.core.clock import utcnow
from app.core.owasp_coverage import COVERAGE
from app.models.api_metrics import UNMATCHED_ROUTE
from app.models.user import ROLES_REQUIRING_MFA, Role
from app.schemas.api_security import (
    EndpointMetrics,
    InventoryItem,
    InventoryResponse,
    InventorySummary,
    OwaspCategory,
    OwaspResponse,
)

WINDOW = timedelta(hours=24)
FORBIDDEN_ALERT = 5  # 403s in the window that mark an endpoint "elevated"
SCAN_NOTE = "Not scanned yet: authenticated DAST runs arrive in Phase 8."
RISK_ORDER = {Risk.CRITICAL: 0, Risk.HIGH: 1, Risk.MEDIUM: 2, Risk.LOW: 3}


@dataclass(frozen=True)
class Access:
    authentication: str
    authorization: str
    roles: tuple[str, ...]
    csrf_protected: bool


def _calls(dependant: Any) -> list[Callable[..., Any]]:
    found: list[Callable[..., Any]] = []
    for dep in dependant.dependencies:
        found.append(dep.call)
        found.extend(_calls(dep))
    return found


def describe_access(route: APIRoute) -> Access:
    calls = _calls(route.dependant)
    csrf = any(getattr(c, "csrf_protection", False) for c in calls)
    guards = [c for c in calls if hasattr(c, "allowed_roles")]
    if public_endpoint in calls:
        return Access(
            "None (public)",
            "Same-origin request with CSRF header" if csrf else "None",
            (),
            csrf,
        )
    if guards:
        roles = tuple(sorted(r.value for r in guards[0].allowed_roles))
        mfa = sorted(r.value for r in ROLES_REQUIRING_MFA if r.value in roles)
        authn = "Session" + (f"; MFA required for {', '.join(mfa)}" if mfa else "")
        authz = (
            "Any role" if set(roles) == {r.value for r in Role} else "Roles: " + ", ".join(roles)
        )
        return Access(authn, authz, roles, csrf)
    if authenticated_setup in calls:
        return Access("Session (account setup may be pending)", "Own account only", (), csrf)
    return Access("UNDECLARED", "UNDECLARED", (), csrf)  # the authz matrix test forbids this


def _status(stats: EndpointMetrics) -> tuple[str, list[str]]:
    reasons: list[str] = []
    if stats.server_errors:
        reasons.append(f"{stats.server_errors} server error(s) in 24h")
    if stats.throttled:
        reasons.append(f"{stats.throttled} request(s) throttled in 24h")
    if stats.forbidden >= FORBIDDEN_ALERT:
        reasons.append(f"{stats.forbidden} forbidden request(s) in 24h")
    if stats.server_errors:
        return "review", reasons
    if reasons:
        return "elevated", reasons
    return "protected", ["Authentication, authorization and rate limit enforced"]


def _metrics(raw: dict[str, int] | None) -> EndpointMetrics:
    raw = raw or {}
    requests = raw.get("requests", 0)
    errors = raw.get("client_errors", 0) + raw.get("server_errors", 0)
    rejections = raw.get("unauthenticated", 0) + raw.get("forbidden", 0) + raw.get("throttled", 0)
    return EndpointMetrics(
        requests=requests,
        error_rate=round(errors / requests, 4) if requests else 0.0,
        client_errors=raw.get("client_errors", 0),
        server_errors=raw.get("server_errors", 0),
        unauthenticated=raw.get("unauthenticated", 0),
        forbidden=raw.get("forbidden", 0),
        throttled=raw.get("throttled", 0),
        security_rejections=rejections,
    )


def build_inventory(
    app: FastAPI, metrics: ApiMetrics, now: datetime | None = None
) -> InventoryResponse:
    now = now or utcnow()
    since = now - WINDOW
    totals = metrics.totals(since) if metrics.enabled else {}
    items: list[InventoryItem] = []
    for ctx in iter_route_contexts(app.routes):
        route, path = ctx.route, ctx.path
        if not isinstance(route, APIRoute) or path is None or not path.startswith("/api/"):
            continue
        for method in sorted(ctx.methods or ()):
            key = (method, path)
            policy = ENDPOINTS.get(key)
            if policy is None:  # the registry test forbids this; never hide an endpoint
                continue
            access = describe_access(route)
            stats = _metrics(totals.get(key))
            status, reasons = _status(stats)
            items.append(
                InventoryItem(
                    method=method,
                    path=path,
                    summary=policy.summary,
                    authentication=access.authentication,
                    authorization=access.authorization,
                    roles=list(access.roles),
                    object_rule=policy.object_rule,
                    csrf_protected=access.csrf_protected,
                    risk=policy.risk.value,
                    rate_limit=policy.rate_limit.description,
                    owasp=[c.code for c in policy.owasp],
                    data=policy.data,
                    metrics=stats,
                    last_scan=None,
                    scan_note=SCAN_NOTE,
                    status=status,
                    status_reasons=reasons,
                )
            )
    items.sort(key=lambda i: (RISK_ORDER[Risk(i.risk)], i.path, i.method))
    unmatched = sum(v["requests"] for (_, route), v in totals.items() if route == UNMATCHED_ROUTE)
    return InventoryResponse(
        generated_at=now,
        window_hours=int(WINDOW.total_seconds() // 3600),
        metrics_enabled=metrics.enabled,
        summary=InventorySummary(
            endpoints=len(items),
            public=sum(1 for i in items if i.authentication.startswith("None")),
            critical=sum(1 for i in items if i.risk == Risk.CRITICAL.value),
            high=sum(1 for i in items if i.risk == Risk.HIGH.value),
            requests=sum(i.metrics.requests for i in items),
            security_rejections=sum(i.metrics.security_rejections for i in items),
            throttled=sum(i.metrics.throttled for i in items),
            unmatched_requests=unmatched,
            needs_attention=sum(1 for i in items if i.status != "protected"),
        ),
        items=items,
    )


def build_owasp() -> OwaspResponse:
    exposure: dict[str, int] = {}
    for policy in ENDPOINTS.values():
        for category in policy.owasp:
            exposure[category.code] = exposure.get(category.code, 0) + 1
    return OwaspResponse(
        edition="OWASP API Security Top 10 (2023)",
        items=[
            OwaspCategory(
                code=c.category.code,
                name=c.category.value.split(" ", 1)[1],
                status=c.status.value,
                controls=list(c.controls),
                evidence=list(c.evidence),
                planned=c.planned,
                exposed_endpoints=exposure.get(c.category.code, 0),
            )
            for c in COVERAGE
        ],
    )
