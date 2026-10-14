"""Security reports for automation (Phase 11): read-only, live and simulated never mixed."""

from __future__ import annotations

import io
import json

import pytest
from fastapi import FastAPI

from app.cli import main
from app.core.clock import utcnow
from app.core.provenance import Provenance
from app.models.security_event import (
    EventCategory,
    EventSource,
    Outcome,
    SecurityEvent,
    Severity,
)
from app.reports import KINDS
from tests.conftest import make_settings

pytestmark = pytest.mark.db


def _run(*argv: str) -> tuple[int, str]:
    out = io.StringIO()
    code = main(["report", *argv], settings=make_settings(), out=out)
    return code, out.getvalue()


def _waf_block(app: FastAPI, provenance: Provenance, rule: str, ip: str) -> None:
    with app.state.session_factory() as db:
        db.add(
            SecurityEvent(
                occurred_at=utcnow(),
                provenance=provenance,
                source=EventSource.WAF,
                category=EventCategory.SQL_INJECTION,
                severity=Severity.HIGH,
                outcome=Outcome.BLOCKED,
                title="Blocked at the edge",
                rule_id=rule,
                source_ip=ip,
                evidence={},
            )
        )
        db.commit()


@pytest.mark.parametrize("kind", KINDS)
def test_every_report_runs_as_text_and_json(db_app: FastAPI, kind: str) -> None:
    code, text = _run(kind)
    assert code == 0, text
    assert text.startswith(f"report: {kind}")
    code, raw = _run(kind, "--format", "json")
    assert code == 0
    assert json.loads(raw)["report"] == kind


def test_the_waf_report_keeps_real_and_simulated_blocks_apart(db_app: FastAPI) -> None:
    _waf_block(db_app, Provenance.REAL_AWS, "AWS-SQLi", "203.0.113.7")
    _waf_block(db_app, Provenance.REAL_AWS, "AWS-SQLi", "203.0.113.7")
    _waf_block(db_app, Provenance.SIMULATED, "SQLI-001", "192.0.2.10")
    report = json.loads(_run("waf", "--format", "json")[1])
    assert report["real_aws"]["blocked"] == 2
    assert report["real_aws"]["by_rule"] == {"AWS-SQLi": 2}
    assert report["real_aws"]["top_sources"] == {"203.0.113.7": 2}
    assert report["simulated"]["blocked"] == 1


def test_the_api_inventory_report_counts_every_route(db_app: FastAPI) -> None:
    report = json.loads(_run("api-inventory", "--format", "json")[1])
    assert report["endpoints"] == 89
    assert "GET /api/v1/health" in report["public"]


def test_certificates_say_they_are_not_connected_locally(db_app: FastAPI) -> None:
    report = json.loads(_run("certificates", "--format", "json")[1])
    assert report["connected"] is False


def test_hours_are_bounded(db_app: FastAPI) -> None:
    with pytest.raises(SystemExit):
        _run("waf", "--hours", "1000")
