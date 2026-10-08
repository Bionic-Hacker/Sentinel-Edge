"""Inspect every API request for attack patterns and record what is found (detect-only).

Pure ASGI, inside SecurityMiddleware (so the correlation ID is set) and inside ClientIpMiddleware
(so the source address is the real client). The request body is observed as the application
reads it (at most 32 KiB is kept), so inspection never changes how a request is processed.
Analysis and recording run after the response, on a worker thread, and never raise: losing a
detection must not fail a request.

Recording is throttled per source IP (DETECTION_EVENTS, 30 a minute): a flood of malicious
requests produces a bounded number of events, and the rest are still counted by API metrics.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import anyio
from sqlalchemy.orm import Session, sessionmaker
from starlette.datastructures import Headers
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.api_policy import DETECTION_EVENTS
from app.core.correlation import get_correlation_id
from app.security.http_analysis import MAX_BODY, InspectedRequest, analyze
from app.security.rate_limit import RateLimiter
from app.services.security_events import EventContext, record_http_analysis

logger = logging.getLogger("sentineledge.http_analysis")

# Inspection exclusions, the application-layer equivalent of WAF rule exclusions: free-text
# fields where analysts legitimately write attack strings (quoting a payload in an incident
# note). Each is a top-level JSON field on one endpoint, reachable only by authenticated roles;
# the path, query string and headers of these requests are still inspected.
INSPECTION_EXCLUSIONS: dict[tuple[str, str], frozenset[str]] = {
    ("POST", "/api/v1/incidents"): frozenset({"title", "summary"}),
    ("PATCH", "/api/v1/incidents/{incident_id}"): frozenset({"title", "summary", "remediation"}),
    ("POST", "/api/v1/incidents/{incident_id}/notes"): frozenset({"body"}),
    ("POST", "/api/v1/incidents/{incident_id}/transitions"): frozenset({"note"}),
}


@dataclass(frozen=True)
class _Observed:
    request: InspectedRequest
    ctx: EventContext


class SecurityEventRecorder:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        limiter: RateLimiter | None,
        *,
        enabled: bool = True,
    ) -> None:
        self.session_factory = session_factory
        self.limiter = limiter
        self.enabled = enabled

    def inspect_and_record(self, observed: _Observed) -> bool:
        """Analyze one request; record an event if anything matched. True when recorded."""
        analysis = analyze(observed.request)
        if not analysis:
            return False
        ip = observed.ctx.source_ip or "unknown"
        if self.limiter is not None:
            decision = self.limiter.check(DETECTION_EVENTS, f"ip:{ip}")
            if decision is not None and not decision.allowed:
                return False
        with self.session_factory() as db:
            record_http_analysis(db, analysis, observed.ctx)
            db.commit()
        return True


class HttpInspectionMiddleware:
    def __init__(self, app: ASGIApp, recorder: SecurityEventRecorder) -> None:
        self.app = app
        self.recorder = recorder

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not self.recorder.enabled:
            await self.app(scope, receive, send)
            return

        body = bytearray()
        status = 500

        async def receive_wrapper() -> Message:
            message = await receive()
            if message["type"] == "http.request" and len(body) < MAX_BODY:
                body.extend(message.get("body", b"")[: MAX_BODY - len(body)])
            return message

        async def send_wrapper(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            await send(message)

        try:
            await self.app(scope, receive_wrapper, send_wrapper)
        finally:
            try:
                observed = self._observe(scope, bytes(body), status)
                await anyio.to_thread.run_sync(self.recorder.inspect_and_record, observed)
            except Exception:  # never let detection break a response
                logger.warning("http_analysis_failed", exc_info=True)

    @staticmethod
    def _observe(scope: Scope, body: bytes, status: int) -> _Observed:
        headers = Headers(scope=scope)
        method = str(scope.get("method", "?"))
        route = scope.get("route")
        templates: dict[int, str] = getattr(scope["app"].state, "route_templates", {})
        template = templates.get(id(route)) if route is not None else None
        raw_path = scope.get("raw_path")
        path = raw_path.decode("latin-1") if raw_path else str(scope.get("path", ""))
        client = scope.get("client")
        request = InspectedRequest(
            method=method,
            path=path,
            query_string=scope.get("query_string", b"").decode("latin-1"),
            user_agent=headers.get("user-agent"),
            referer=headers.get("referer"),
            content_type=headers.get("content-type"),
            body=body,
            route_matched=template is not None,
            excluded_fields=INSPECTION_EXCLUSIONS.get((method, template or ""), frozenset()),
        )
        ctx = EventContext(
            source_ip=client[0] if client else None,
            user_agent=headers.get("user-agent"),
            method=method,
            endpoint=template or str(scope.get("path", ""))[:200],
            status_code=status,
            correlation_id=get_correlation_id(),
        )
        return _Observed(request, ctx)
