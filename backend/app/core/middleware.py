"""Pure-ASGI middleware: correlation IDs, security headers, structured access logging.

Implemented as raw ASGI (not BaseHTTPMiddleware) so headers are applied to *every* response,
including those produced by exception handlers and by Starlette for unmatched routes.
"""

from __future__ import annotations

import logging
import time

from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.correlation import (
    CORRELATION_HEADER,
    new_correlation_id,
    reset_correlation_id,
    sanitize_inbound_id,
    set_correlation_id,
)
from app.core.errors import internal_error_response
from app.core.security_headers import API_SECURITY_HEADERS

access_log = logging.getLogger("sentineledge.access")


class SecurityMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        inbound = Headers(scope=scope).get(CORRELATION_HEADER)
        correlation_id = sanitize_inbound_id(inbound) or new_correlation_id()
        token = set_correlation_id(correlation_id)
        started = time.perf_counter()
        status_code = 500
        response_started = False

        async def send_wrapper(message: Message) -> None:
            nonlocal status_code, response_started
            if message["type"] == "http.response.start":
                response_started = True
                status_code = message["status"]
                headers = MutableHeaders(scope=message)
                for name, value in API_SECURITY_HEADERS.items():
                    headers[name] = value
                headers[CORRELATION_HEADER] = correlation_id
                # Do not advertise the server implementation.
                if "server" in headers:
                    del headers["server"]
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        except Exception as exc:
            if response_started:
                raise  # cannot replace a response already on the wire
            await internal_error_response(exc)(scope, receive, send_wrapper)
        finally:
            client = scope.get("client")
            # Path only: query strings may carry secrets or attack payloads.
            access_log.info(
                "request",
                extra={
                    "http_method": scope.get("method"),
                    "http_path": scope.get("path"),
                    "http_status": status_code,
                    "duration_ms": round((time.perf_counter() - started) * 1000, 2),
                    "client_ip": client[0] if client else None,
                },
            )
            reset_correlation_id(token)
