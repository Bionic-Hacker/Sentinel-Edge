"""Secure, uniform error responses.

Clients receive a stable envelope with a generic message and the correlation ID; details
(stack traces, SQL errors, internal paths, submitted values) are logged internally only.
"""

from __future__ import annotations

import logging
from http import HTTPStatus

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.correlation import get_correlation_id

logger = logging.getLogger("sentineledge.errors")


def error_response(
    status_code: int, code: str, message: str, details: list[dict[str, str]] | None = None
) -> JSONResponse:
    body: dict[str, object] = {
        "error": {"code": code, "message": message, "correlation_id": get_correlation_id()}
    }
    if details:
        body["error"]["details"] = details  # type: ignore[index]
    return JSONResponse(status_code=status_code, content=body)


async def http_exception_handler(_: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, StarletteHTTPException):  # type narrowing without `assert`
        raise exc
    try:
        phrase = HTTPStatus(exc.status_code).phrase
    except ValueError:
        phrase = "Error"
    # Use the standard phrase, never exc.detail, unless a handler opted in (Phase 2+).
    code = phrase.lower().replace(" ", "_").replace("-", "_")
    return error_response(exc.status_code, code, phrase)


async def validation_exception_handler(_: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, RequestValidationError):
        raise exc
    # Report *where* and *what kind* of problem — never echo the submitted input back,
    # which would reflect attacker payloads and could expose sensitive values.
    details = [
        {
            "location": ".".join(str(part) for part in err.get("loc", ())),
            "type": str(err.get("type", "invalid")),
        }
        for err in exc.errors()
    ]
    return error_response(422, "validation_error", "Request validation failed", details)


def internal_error_response(exc: BaseException) -> JSONResponse:
    """Generic 500. Invoked by SecurityMiddleware so security headers are still applied."""
    logger.error("unhandled_exception", exc_info=exc)
    return error_response(500, "internal_error", "An internal error occurred")


def register_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    # Unhandled exceptions are caught in SecurityMiddleware (see internal_error_response),
    # because Starlette's outermost error middleware would bypass our header injection.
