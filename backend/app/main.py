"""SentinelEdge API application factory.

Run with: ``uvicorn --factory app.main:create_app`` (see Dockerfile).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from starlette.concurrency import run_in_threadpool

from app.api.v1.router import api_v1
from app.core.api_metrics import ApiMetrics, ApiMetricsMiddleware
from app.core.api_policy import build_route_templates
from app.core.client_ip import ClientIpMiddleware
from app.core.config import Settings, get_settings
from app.core.errors import register_error_handlers
from app.core.http_inspection import HttpInspectionMiddleware, SecurityEventRecorder
from app.core.logging import configure_logging
from app.core.middleware import HostCheckMiddleware, SecurityMiddleware
from app.core.rate_limiting import enforce_ip_limits
from app.db.session import build_engine, build_session_factory
from app.security.mfa import MfaService
from app.security.passwords import PasswordHasher
from app.security.rate_limit import RateLimiter
from app.security.tokens import TokenService
from app.services import aws_edge

logger = logging.getLogger("sentineledge.main")


async def _aws_edge_loop(application: FastAPI, settings: Settings) -> None:
    """Sync the edge feeds shortly after start, then every aws_sync_interval_seconds."""
    await asyncio.sleep(30)
    while True:
        try:
            await run_in_threadpool(aws_edge.sync, application.state.session_factory, settings)
        except Exception as exc:  # the loop must outlive any one failure
            logger.warning("aws_edge_loop_failed", extra={"error_type": type(exc).__name__})
        await asyncio.sleep(settings.aws_sync_interval_seconds)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level.value)

    # The engine is lazy: no connection is opened until the first query.
    engine = build_engine(settings)

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        # In AWS, read WAF blocks and check certificates on a timer (ADR-0029).
        task = (
            asyncio.create_task(_aws_edge_loop(application, settings))
            if settings.aws_edge_enabled
            else None
        )
        yield
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        engine.dispose()

    docs = settings.enable_api_docs
    app = FastAPI(
        title="SentinelEdge API",
        version=settings.app_version,
        docs_url="/api/docs" if docs else None,
        redoc_url=None,
        openapi_url="/api/openapi.json" if docs else None,
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = build_session_factory(engine)
    # Security services hold key material; constructing them fails closed if keys are missing.
    app.state.tokens = TokenService(settings)
    app.state.hasher = PasswordHasher(settings)
    app.state.mfa = MfaService(settings)
    app.state.rate_limiter = RateLimiter(
        app.state.session_factory, enabled=settings.rate_limit_enabled
    )
    app.state.api_metrics = ApiMetrics(
        app.state.session_factory, enabled=settings.api_metrics_enabled
    )
    app.state.event_recorder = SecurityEventRecorder(
        app.state.session_factory,
        app.state.rate_limiter if settings.rate_limit_enabled else None,
        enabled=settings.http_analysis_enabled,
    )

    # Order matters: the last added middleware runs first. SecurityMiddleware is outermost so
    # that every response — including Host rejections and errors — gets headers and a
    # correlation ID.
    # The Host allow-list, except for the liveness probe that load balancers address by IP.
    app.add_middleware(HostCheckMiddleware, allowed_hosts=settings.trusted_hosts)
    # Detect-only attack analysis (Phase 7): sees the routed request and its final status.
    app.add_middleware(HttpInspectionMiddleware, recorder=app.state.event_recorder)
    app.add_middleware(ApiMetricsMiddleware, metrics=app.state.api_metrics)
    app.add_middleware(SecurityMiddleware)
    # Outermost: resolve the real client IP first, so logs, audit and limits all agree on it.
    app.add_middleware(ClientIpMiddleware, trusted_proxy_cidrs=settings.trusted_proxy_cidrs)

    register_error_handlers(app)
    # Per-IP limits run on every API route before authentication (ADR-0017).
    app.include_router(api_v1, dependencies=[Depends(enforce_ip_limits)])
    app.state.route_templates = build_route_templates(app)
    return app
