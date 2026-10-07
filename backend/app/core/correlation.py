"""Request correlation IDs, propagated through logs, errors, and (Phase 2) audit records."""

from __future__ import annotations

import re
import uuid
from contextvars import ContextVar, Token

CORRELATION_HEADER = "X-Request-ID"
# Accept only short, inert identifiers from upstream (CloudFront/ALB/clients).
# Anything else is discarded to prevent log injection and header splitting.
_SAFE_ID = re.compile(r"^[A-Za-z0-9\-_.]{8,64}$")

_correlation_id: ContextVar[str | None] = ContextVar("correlation_id", default=None)


def new_correlation_id() -> str:
    return str(uuid.uuid4())


def sanitize_inbound_id(value: str | None) -> str | None:
    if value and _SAFE_ID.fullmatch(value):
        return value
    return None


def get_correlation_id() -> str | None:
    return _correlation_id.get()


def set_correlation_id(value: str) -> Token[str | None]:
    return _correlation_id.set(value)


def reset_correlation_id(token: Token[str | None]) -> None:
    _correlation_id.reset(token)
