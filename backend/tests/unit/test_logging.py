import json
import logging

import pytest

from app.core.correlation import reset_correlation_id, set_correlation_id
from app.core.logging import REDACTED, JsonFormatter, redact


@pytest.mark.parametrize(
    "key",
    ["password", "Authorization", "refresh_token", "api_key", "X-API-Key", "cookie", "db_secret"],
)
def test_sensitive_keys_redacted(key: str) -> None:
    assert redact({key: "value"}) == {key: REDACTED}


def test_nested_structures_redacted() -> None:
    data = {"request": {"headers": {"authorization": "Bearer abc"}, "path": "/x"}}
    assert redact(data) == {"request": {"headers": {"authorization": REDACTED}, "path": "/x"}}


def test_control_characters_neutralised() -> None:
    assert redact("user\nFAKE LOG LINE\r") == "user?FAKE LOG LINE?"


def _record(msg: str, **extra: object) -> logging.LogRecord:
    record = logging.LogRecord("t", logging.INFO, __file__, 1, msg, None, None)
    for k, v in extra.items():
        setattr(record, k, v)
    return record


def test_formatter_emits_json_with_correlation_id_and_redaction() -> None:
    token = set_correlation_id("corr-12345678")
    try:
        line = JsonFormatter().format(_record("login attempt", password="hunter2", user="a"))
    finally:
        reset_correlation_id(token)
    payload = json.loads(line)
    assert payload["correlation_id"] == "corr-12345678"
    assert payload["password"] == REDACTED
    assert payload["user"] == "a"
    assert "hunter2" not in line


def test_formatter_includes_exception_internally() -> None:
    try:
        raise ValueError("boom")
    except ValueError:
        import sys

        record = logging.LogRecord("t", logging.ERROR, __file__, 1, "x", None, sys.exc_info())
    assert "ValueError" in json.loads(JsonFormatter().format(record))["exception"]
