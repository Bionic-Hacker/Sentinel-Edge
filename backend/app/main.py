"""SentinelEdge API application factory.

Run with: ``uvicorn --factory app.main:create_app`` (see Dockerfile).
"""

from __future__ import annotations

from fastapi import FastAPI
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.api.v1.router import api_v1
from app.core.config import Settings, get_settings
from app.core.errors import register_error_handlers
from app.core.logging import configure_logging
from app.core.middleware import SecurityMiddleware


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level.value)

    docs = settings.enable_api_docs
    app = FastAPI(
        title="SentinelEdge API",
        version=settings.app_version,
        docs_url="/api/docs" if docs else None,
        redoc_url=None,
        openapi_url="/api/openapi.json" if docs else None,
    )

    # Order matters: the last added middleware runs first. SecurityMiddleware is outermost so
    # that every response — including Host rejections and errors — gets headers and a
    # correlation ID.
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.trusted_hosts)
    app.add_middleware(SecurityMiddleware)

    register_error_handlers(app)
    app.include_router(api_v1)
    return app
