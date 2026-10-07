"""Single source of the current time, so expiry logic can be tested deterministically."""

from __future__ import annotations

from datetime import UTC, datetime


def utcnow() -> datetime:
    return datetime.now(UTC)
