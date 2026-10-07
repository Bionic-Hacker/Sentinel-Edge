"""Per-endpoint request metrics for the API Security Center (spec §14).

Counts every /api request against its route TEMPLATE (never the raw path, which can carry IDs
or attack payloads) per hour: requests, 4xx, 5xx, 401, 403 and 429. Requests that match no route
are counted under "(unmatched)", a signal of probing for undocumented endpoints (OWASP API9).

Recording happens after the response is sent, on a worker thread, and never raises: losing a
metric must not fail a request.
"""

from __future__ import annotations

import logging
import random
from datetime import datetime

import anyio
from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.models.api_metrics import UNMATCHED_ROUTE

logger = logging.getLogger("sentineledge.metrics")

RETENTION_DAYS = 30
PRUNE_PROBABILITY = 0.001

_RECORD = text(
    """
    INSERT INTO sentinel.api_endpoint_stats AS s
        (method, route, hour, requests, client_errors, server_errors,
         unauthenticated, forbidden, throttled)
    VALUES (:method, :route, date_trunc('hour', now()), 1, :c4, :c5, :c401, :c403, :c429)
    ON CONFLICT (method, route, hour) DO UPDATE SET
        requests = s.requests + 1,
        client_errors = s.client_errors + :c4,
        server_errors = s.server_errors + :c5,
        unauthenticated = s.unauthenticated + :c401,
        forbidden = s.forbidden + :c403,
        throttled = s.throttled + :c429
    """
)
_PRUNE = text("DELETE FROM sentinel.api_endpoint_stats WHERE hour < now() - interval '30 days'")
_TOTALS = text(
    """
    SELECT method, route,
           sum(requests) AS requests, sum(client_errors) AS client_errors,
           sum(server_errors) AS server_errors, sum(unauthenticated) AS unauthenticated,
           sum(forbidden) AS forbidden, sum(throttled) AS throttled
    FROM sentinel.api_endpoint_stats
    WHERE hour >= :since
    GROUP BY method, route
    """
)


class ApiMetrics:
    def __init__(self, session_factory: sessionmaker[Session], *, enabled: bool = True) -> None:
        self.session_factory = session_factory
        self.enabled = enabled

    def record(self, method: str, route: str, status: int) -> None:
        params = {
            "method": method[:10],
            "route": route[:200],
            "c4": int(400 <= status < 500),
            "c5": int(status >= 500),
            "c401": int(status == 401),
            "c403": int(status == 403),
            "c429": int(status == 429),
        }
        with self.session_factory() as db:
            db.execute(_RECORD, params)
            # Not security relevant: only decides when to drop rows past retention.
            if random.random() < PRUNE_PROBABILITY:  # noqa: S311  # nosec B311
                db.execute(_PRUNE)
            db.commit()

    def totals(self, since: datetime) -> dict[tuple[str, str], dict[str, int]]:
        """Counters summed since `since`, keyed by (method, route template)."""
        with self.session_factory() as db:
            rows = db.execute(_TOTALS, {"since": since}).mappings().all()
        return {
            (row["method"], row["route"]): {
                key: int(row[key])
                for key in (
                    "requests",
                    "client_errors",
                    "server_errors",
                    "unauthenticated",
                    "forbidden",
                    "throttled",
                )
            }
            for row in rows
        }


class ApiMetricsMiddleware:
    """Pure ASGI: sits inside SecurityMiddleware (which turns crashes into 500s) and outside
    TrustedHostMiddleware (so Host-header rejections are counted too)."""

    def __init__(self, app: ASGIApp, metrics: ApiMetrics) -> None:
        self.app = app
        self.metrics = metrics

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] != "http"
            or not self.metrics.enabled
            or not str(scope.get("path", "")).startswith("/api/")
        ):
            await self.app(scope, receive, send)
            return

        status = 500

        async def send_wrapper(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            route = scope.get("route")
            templates: dict[int, str] = getattr(scope["app"].state, "route_templates", {})
            template = templates.get(id(route), UNMATCHED_ROUTE) if route else UNMATCHED_ROUTE
            try:
                await anyio.to_thread.run_sync(
                    self.metrics.record, str(scope.get("method", "?")), template, status
                )
            except Exception:  # never let metrics break a response
                logger.warning("api_metrics_record_failed", exc_info=True)
