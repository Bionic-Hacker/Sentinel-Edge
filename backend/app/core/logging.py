"""Structured JSON logging with secret redaction.

Every record is a single JSON object (CloudWatch Logs Insights friendly, Phase 4) carrying the
request correlation ID. Values under sensitive-looking keys are redacted before serialization
so a careless ``extra={...}`` cannot leak credentials into logs, and control characters are
neutralised so attacker-controlled strings cannot forge log lines.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from datetime import UTC, datetime
from typing import Any

from app.core.correlation import get_correlation_id

REDACTED = "[REDACTED]"
_SENSITIVE_KEY = re.compile(
    r"(pass(word)?|secret|token|authorization|cookie|api[_-]?key|credential|session|private[_-]?key)",
    re.IGNORECASE,
)
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")

# Attributes every LogRecord has; anything else arrived via `extra=`.
_STANDARD_ATTRS = frozenset(vars(logging.LogRecord("", 0, "", 0, "", None, None))) | {
    "message",
    "asctime",
    "taskName",
    "color_message",  # uvicorn's ANSI-coloured duplicate of `message`
}


def redact(value: Any, key: str | None = None) -> Any:
    """Recursively redact values stored under sensitive-looking keys."""
    if key is not None and _SENSITIVE_KEY.search(key):
        return REDACTED
    if isinstance(value, dict):
        return {k: redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [redact(v) for v in value]
    if isinstance(value, str):
        return _CONTROL_CHARS.sub("?", value)
    return value


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": redact(record.getMessage()),
            "correlation_id": get_correlation_id(),
        }
        extras = {k: v for k, v in vars(record).items() if k not in _STANDARD_ATTRS}
        payload.update(redact(extras))
        if record.exc_info:
            # Full detail stays in internal logs only; never in HTTP responses.
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: str) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
    # Uvicorn's access log is replaced by the structured access-log middleware.
    logging.getLogger("uvicorn.access").disabled = True
    for name in ("uvicorn", "uvicorn.error"):
        logging.getLogger(name).handlers[:] = []
        logging.getLogger(name).propagate = True
