"""Security exceptions and change management (Phase 10, ADR-0023): separation of duties in the
service and the database, permanent decisions, enforced expiry, the scan gate's register
generated from approved exceptions, and change requests that drive the simulated WAF."""

from __future__ import annotations

import io
import re
import uuid
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError, IntegrityError, ProgrammingError

from app import cli
from app.models.user import Role
from app.scanning.gate import load_acceptances
from app.services import risk_governance
from tests.conftest import make_settings, run_migrations
from tests.helpers import audit_entries, bearer, create_user, session_token

pytestmark = [pytest.mark.security, pytest.mark.db]

TODAY = datetime.now(UTC).date()  # the service's notion of today (UTC)


@pytest.fixture
def people(db_app: FastAPI) -> dict[str, Any]:
    specs = {
        "admin": Role.ADMIN,
        "lead": Role.SECURITY_ENGINEER,
        "analyst": Role.ANALYST,
        "viewer": Role.VIEWER,
        "dev": Role.DEVELOPER,
    }
    out = {}
    for name, role in specs.items():
        mfa = role in (Role.ADMIN, Role.SECURITY_ENGINEER)
        user = create_user(
            db_app,
            f"{name}@example.com",
            role=role,
            mfa_enabled=mfa,
            mfa_secret=b"x" if mfa else None,
        )
        out[name] = {"user": user, "h": bearer(session_token(db_app, user))}
    return out


def exception_body(**overrides: Any) -> dict[str, Any]:
    body = {
        "title": "Hold a library on its current major version",
        "scope": "dependency",
        "scope_ref": "frontend: example-lib",
        "risk_level": "high",
        "risk": "The held version no longer receives feature updates upstream.",
        "justification": "The next major version breaks the accessibility lint rules we require.",
        "compensating_control": "npm audit gates every CI run; minor and patch updates still flow.",
        "control_refs": ["C-CICD-02"],
        "expires_on": (TODAY + timedelta(days=60)).isoformat(),
    }
    return {**body, **overrides}


def change_body(**overrides: Any) -> dict[str, Any]:
    body = {
        "title": "Tighten the session idle timeout",
        "change_type": "configuration",
        "description": "Reduce the refresh-token idle timeout from 12 to 8 hours.",
        "risk_level": "medium",
        "impact": "Users idle for more than eight hours sign in again; nothing else changes.",
        "rollback_plan": "Revert the configuration pull request and redeploy the API.",
        "validation_plan": "Sign in, wait past the timeout in a test, confirm a 401 on refresh.",
    }
    return {**body, **overrides}


def request_exception(client: TestClient, h: dict[str, str], **overrides: Any) -> dict[str, Any]:
    r = client.post("/api/v1/exceptions", json=exception_body(**overrides), headers=h)
    assert r.status_code == 201, r.text
    data: dict[str, Any] = r.json()
    return data


def submit_change(client: TestClient, h: dict[str, str], **overrides: Any) -> dict[str, Any]:
    r = client.post("/api/v1/change-requests", json=change_body(**overrides), headers=h)
    assert r.status_code == 201, r.text
    data: dict[str, Any] = r.json()
    return data


def move(client: TestClient, h: dict[str, str], c: dict[str, Any], to: str, **extra: Any) -> Any:
    return client.post(
        f"/api/v1/change-requests/{c['id']}/transition",
        json={"to": to, "version": c["version"], **extra},
        headers=h,
    )


# --- exceptions -------------------------------------------------------------------------------


def test_migration_imports_the_documented_exceptions(migrator_engine: Engine) -> None:
    run_migrations(migrator_engine, "0010", downgrade=True)
    run_migrations(migrator_engine)
    with migrator_engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT number, status, imported, approver_label, expires_on "
                "FROM sentinel.exceptions ORDER BY number"
            )
        ).all()
    assert [(r.number, r.status, r.imported) for r in rows] == [
        (1, "approved", True),
        (2, "approved", True),
    ]
    assert {r.expires_on for r in rows} == {date(2027, 1, 7)}


def test_whoever_asks_cannot_approve(
    db_app: FastAPI, db_client: TestClient, people: dict[str, Any]
) -> None:
    lead, admin = people["lead"]["h"], people["admin"]["h"]
    e = request_exception(db_client, lead)
    assert re.fullmatch(r"EXC-\d{4}", e["reference"])
    assert e["status"] == "requested"
    assert e["permissions"] == {
        "can_decide": False,
        "can_close": True,
        "separation_of_duties": True,
    }
    url = f"/api/v1/exceptions/{e['id']}"
    own = db_client.post(f"{url}/decision", json={"approve": True, "version": 1}, headers=lead)
    assert own.status_code == 409
    assert own.json()["error"]["code"] == "separation_of_duties"

    other = db_client.get(url, headers=admin).json()
    assert other["permissions"]["can_decide"] is True
    approved = db_client.post(
        f"{url}/decision", json={"approve": True, "note": "", "version": 1}, headers=admin
    )
    assert approved.status_code == 200, approved.text
    body = approved.json()
    assert (body["status"], body["approver_label"], body["days_left"]) == (
        "approved",
        "admin@example.com",
        60,
    )
    assert [h["action"] for h in body["history"]] == ["exception.requested", "exception.approved"]
    again = db_client.post(f"{url}/decision", json={"approve": False, "version": 2}, headers=admin)
    assert again.status_code == 409


def test_the_database_refuses_self_approval_and_rewritten_decisions(
    db_app: FastAPI, db_client: TestClient, people: dict[str, Any], migrator_engine: Engine
) -> None:
    e = request_exception(db_client, people["lead"]["h"])
    with migrator_engine.connect() as conn, pytest.raises(IntegrityError):
        conn.execute(
            text(
                "UPDATE sentinel.exceptions SET approver_id = requester_id, "
                "approver_label = 'x', status = 'approved' WHERE id = :id"
            ),
            {"id": e["id"]},
        )
    db_client.post(
        f"/api/v1/exceptions/{e['id']}/decision",
        json={"approve": True, "version": 1},
        headers=people["admin"]["h"],
    )
    for sql in (
        "UPDATE sentinel.exceptions SET justification = 'rewritten afterwards' WHERE id = :id",
        "UPDATE sentinel.exceptions SET expires_on = expires_on + 365 WHERE id = :id",
        "UPDATE sentinel.exceptions SET approver_label = 'someone else' WHERE id = :id",
    ):
        # Not even the table owner can rewrite a decided exception.
        with (
            migrator_engine.connect() as conn,
            pytest.raises(DBAPIError, match="cannot be rewritten"),
        ):
            conn.execute(text(sql), {"id": e["id"]})


@pytest.mark.parametrize(
    ("overrides", "status", "code"),
    [
        ({"expires_on": (TODAY + timedelta(days=91)).isoformat()}, 422, "expiry_too_long"),
        (
            {"risk_level": "critical", "expires_on": (TODAY + timedelta(days=31)).isoformat()},
            422,
            "expiry_too_long",
        ),
        ({"expires_on": TODAY.isoformat()}, 422, "expiry_in_past"),
        ({"control_refs": ["C-NOPE-01"]}, 422, "unknown_control"),
        ({"scope": "scan_finding"}, 422, None),  # a gate match is required
        ({"gate_match": {"tool": "trivy", "rule": "CVE-2026-1"}}, 422, None),  # only for findings
        (
            {"scope": "scan_finding", "gate_match": {"fingerprint": "ab" * 16, "tool": "zap"}},
            422,
            None,
        ),
        ({"justification": "too short"}, 422, None),
        ({"approver": "me"}, 422, None),
    ],
)
def test_requests_are_validated(
    db_client: TestClient,
    people: dict[str, Any],
    overrides: dict[str, Any],
    status: int,
    code: str | None,
) -> None:
    r = db_client.post(
        "/api/v1/exceptions", json=exception_body(**overrides), headers=people["lead"]["h"]
    )
    assert r.status_code == status, r.text
    if code:
        assert r.json()["error"]["code"] == code


def test_rejection_withdrawal_and_closure_need_reasons(
    db_client: TestClient, people: dict[str, Any]
) -> None:
    lead, admin = people["lead"]["h"], people["admin"]["h"]
    e = request_exception(db_client, lead)
    url = f"/api/v1/exceptions/{e['id']}"
    silent = db_client.post(f"{url}/decision", json={"approve": False, "version": 1}, headers=admin)
    assert silent.json()["error"]["code"] == "note_required"
    rejected = db_client.post(
        f"{url}/decision",
        json={"approve": False, "note": "Fix it instead: upgrade is one PR.", "version": 1},
        headers=admin,
    ).json()
    assert rejected["status"] == "rejected"
    assert rejected["permissions"]["can_close"] is False

    w = request_exception(db_client, lead)
    analyst = db_client.post(
        f"/api/v1/exceptions/{w['id']}/close",
        json={"note": "Not mine to withdraw.", "version": 1},
        headers=people["analyst"]["h"],
    )
    assert analyst.status_code == 403
    withdrawn = db_client.post(
        f"/api/v1/exceptions/{w['id']}/close",
        json={"note": "Upgraded after all; not needed.", "version": 1},
        headers=lead,
    ).json()
    assert withdrawn["status"] == "withdrawn"

    c = request_exception(db_client, lead)
    db_client.post(
        f"/api/v1/exceptions/{c['id']}/decision",
        json={"approve": True, "version": 1},
        headers=admin,
    )
    closed = db_client.post(
        f"/api/v1/exceptions/{c['id']}/close",
        json={"note": "The upstream fix shipped; upgraded.", "version": 2},
        headers=admin,
    ).json()
    assert (closed["status"], closed["end_note"]) == (
        "closed",
        "The upstream fix shipped; upgraded.",
    )
    listing = db_client.get("/api/v1/exceptions", headers=people["viewer"]["h"]).json()
    assert listing["counts"]["rejected"] == listing["counts"]["withdrawn"] == 1
    assert listing["counts"]["closed"] == 1


def test_an_approved_exception_expires_on_its_date(
    db_app: FastAPI,
    db_client: TestClient,
    people: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    e = request_exception(
        db_client, people["lead"]["h"], expires_on=(TODAY + timedelta(days=10)).isoformat()
    )
    db_client.post(
        f"/api/v1/exceptions/{e['id']}/decision",
        json={"approve": True, "version": 1},
        headers=people["admin"]["h"],
    )
    listing = db_client.get("/api/v1/exceptions", headers=people["viewer"]["h"]).json()
    assert listing["counts"]["expiring_30d"] == 1

    monkeypatch.setattr(risk_governance, "today", lambda: TODAY + timedelta(days=11))
    after = db_client.get(f"/api/v1/exceptions/{e['id']}", headers=people["viewer"]["h"]).json()
    assert after["status"] == "expired"
    assert after["end_note"].startswith("Expired on")
    (expired,) = audit_entries(db_app, "exception.expired")
    assert expired.actor_label == "system:governance"


def test_approved_scan_finding_exceptions_become_the_gate_register(
    db_app: FastAPI, db_client: TestClient, people: dict[str, Any], tmp_path: Path
) -> None:
    lead, admin = people["lead"]["h"], people["admin"]["h"]
    accepted = request_exception(
        db_client,
        lead,
        title='Accept a base-image "curl" CVE until the fix lands',
        scope="scan_finding",
        scope_ref="sentineledge-api image: curl",
        gate_match={"tool": "trivy", "rule": "CVE-2026-0001", "component": "curl@*"},
    )
    db_client.post(
        f"/api/v1/exceptions/{accepted['id']}/decision",
        json={"approve": True, "version": 1},
        headers=admin,
    )
    request_exception(  # still requested: not in the register
        db_client,
        lead,
        scope="scan_finding",
        gate_match={"fingerprint": "ab" * 16},
    )

    out = io.StringIO()
    assert cli.main(["export-accepted-risks"], settings=make_settings(), out=out) == 0
    register = tmp_path / "accepted-findings.toml"
    register.write_text(out.getvalue())
    (entry,) = load_acceptances(register)
    assert (entry.id, entry.tool, entry.rule, entry.component) == (
        accepted["reference"],
        "trivy",
        "CVE-2026-0001",
        "curl@*",
    )
    assert entry.approver == "admin@example.com"
    assert entry.expires == TODAY + timedelta(days=60)
    assert out.getvalue().startswith("# Accepted risks for the scan gate")

    other = db_client.post(
        "/api/v1/applications",
        json={
            "slug": "payments-api",
            "name": "Payments API",
            "environment": "production",
            "criticality": "high",
            "domain": "payments.corp.example",
        },
        headers=admin,
    ).json()
    elsewhere = db_client.post(
        "/api/v1/exceptions",
        json=exception_body(
            application_id=other["id"], scope="scan_finding", gate_match={"fingerprint": "cd" * 16}
        ),
        headers=lead,
    )
    assert elsewhere.json()["error"]["code"] == "gate_is_platform_only"


def test_developers_raise_requests_only_for_their_own_applications(
    db_app: FastAPI, db_client: TestClient, people: dict[str, Any]
) -> None:
    admin, dev = people["admin"]["h"], people["dev"]["h"]
    created = db_client.post(
        "/api/v1/applications",
        json={
            "slug": "dev-app",
            "name": "Dev App",
            "environment": "staging",
            "criticality": "medium",
            "domain": "dev.corp.example",
            "owner_id": str(people["dev"]["user"].id),
        },
        headers=admin,
    )
    assert created.status_code == 201, created.text
    platform_request = db_client.post("/api/v1/exceptions", json=exception_body(), headers=dev)
    assert platform_request.status_code == 404
    assert audit_entries(db_app, "authz.denied")[-1].resource_type == "application"

    mine = request_exception(db_client, dev, application_id=created.json()["id"])
    request_exception(db_client, people["lead"]["h"])  # SentinelEdge's: not visible to dev
    listed = db_client.get("/api/v1/exceptions", headers=dev).json()["items"]
    assert [e["id"] for e in listed] == [mine["id"]]
    decide = db_client.post(
        f"/api/v1/exceptions/{mine['id']}/decision",
        json={"approve": True, "version": 1},
        headers=dev,
    )
    assert decide.status_code == 403


# --- change requests --------------------------------------------------------------------------


def test_a_change_goes_from_request_to_validation(
    db_app: FastAPI, db_client: TestClient, people: dict[str, Any]
) -> None:
    lead, admin = people["lead"]["h"], people["admin"]["h"]
    c = submit_change(db_client, lead)
    assert (c["reference"], c["status"]) == ("CHG-0001", "submitted")
    assert c["available_moves"] == ["cancelled"]
    assert c["separation_of_duties"] is True
    self_approve = move(db_client, lead, c, "approved")
    assert self_approve.json()["error"]["code"] == "separation_of_duties"

    c = move(db_client, admin, c, "approved", note="Reviewed the plan.").json()
    assert (c["status"], c["approver_label"]) == ("approved", "admin@example.com")
    missing_ref = move(db_client, lead, c, "implemented")
    assert missing_ref.json()["error"]["code"] == "implementation_ref_required"
    c = move(
        db_client,
        lead,
        c,
        "implemented",
        implementation_ref="https://github.com/Bionic-Hacker/Sentinel-Edge/pull/99",
    ).json()
    assert c["implemented_by_label"] == "lead@example.com"
    assert set(c["available_moves"]) == {"validated", "rolled_back"}
    stale = db_client.post(
        f"/api/v1/change-requests/{c['id']}/transition",
        json={"to": "validated", "note": "Checked it works.", "version": 1},
        headers=admin,
    )
    assert stale.json()["error"]["code"] == "stale_version"
    unexplained = move(db_client, admin, c, "validated")
    assert unexplained.json()["error"]["code"] == "note_required"
    c = move(
        db_client, admin, c, "validated", note="Refresh refused after 8 hours in staging."
    ).json()
    assert c["status"] == "validated"
    assert c["available_moves"] == []
    assert [h["action"] for h in c["history"]] == [
        "change_request.submitted",
        "change_request.approved",
        "change_request.implemented",
        "change_request.validated",
    ]


def test_a_waf_change_drives_the_simulated_waf_and_rolls_back(
    db_app: FastAPI, db_client: TestClient, people: dict[str, Any]
) -> None:
    lead, admin = people["lead"]["h"], people["admin"]["h"]

    def mode() -> str:
        rules = db_client.get("/api/v1/simulator/waf-rules", headers=admin).json()["items"]
        found: str = next(r["mode"] for r in rules if r["rule_id"] == "SQLI-001")
        return found

    c = submit_change(
        db_client,
        lead,
        title="Count SQLI-001 while tuning a false positive",
        change_type="waf_rule",
        target={"rule_id": "SQLI-001", "mode": "count"},
    )
    c = move(db_client, admin, c, "approved").json()
    assert mode() == "block"
    c = move(db_client, lead, c, "implemented").json()
    assert (mode(), c["previous_state"], c["implementation_ref"]) == (
        "count",
        {"mode": "block"},
        "simulated-waf:SQLI-001",
    )
    c = move(db_client, lead, c, "rolled_back", note="Blocked a real customer request.").json()
    assert (c["status"], mode()) == ("rolled_back", "block")
    changes = audit_entries(db_app, "simulator.waf_rule_changed")
    assert [(e.details["to"], e.details["change_request"]) for e in changes] == [
        ("count", c["reference"]),
        ("block", c["reference"]),
    ]


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        (
            {"change_type": "waf_rule", "target": {"rule_id": "NOPE-001", "mode": "count"}},
            "unknown_waf_rule",
        ),
        ({"change_type": "waf_rule"}, None),  # a target is required
        ({"target": {"rule_id": "SQLI-001", "mode": "count"}}, None),  # only for waf_rule
        ({"rollback_plan": "revert"}, None),  # a real rollback plan
    ],
)
def test_change_requests_are_validated(
    db_client: TestClient, people: dict[str, Any], overrides: dict[str, Any], code: str | None
) -> None:
    r = db_client.post(
        "/api/v1/change-requests", json=change_body(**overrides), headers=people["lead"]["h"]
    )
    assert r.status_code == 422, r.text
    if code:
        assert r.json()["error"]["code"] == code


def test_a_cancelled_change_cannot_be_revived_or_rewritten(
    db_client: TestClient, people: dict[str, Any], migrator_engine: Engine
) -> None:
    lead = people["lead"]["h"]
    c = submit_change(db_client, lead)
    c = move(db_client, lead, c, "cancelled", note="Superseded by CHG-0002.").json()
    assert move(db_client, people["admin"]["h"], c, "approved").status_code == 409
    with migrator_engine.connect() as conn, pytest.raises(DBAPIError, match="cannot be rewritten"):
        conn.execute(
            text("UPDATE sentinel.change_requests SET rollback_plan = 'none' WHERE id = :id"),
            {"id": c["id"]},
        )


def test_viewers_read_but_cannot_act(db_client: TestClient, people: dict[str, Any]) -> None:
    c = submit_change(db_client, people["lead"]["h"])
    viewer = people["viewer"]["h"]
    seen = db_client.get(f"/api/v1/change-requests/{c['id']}", headers=viewer).json()
    assert seen["available_moves"] == []
    assert move(db_client, viewer, c, "cancelled", note="Not allowed here.").status_code == 403
    assert (
        db_client.post("/api/v1/change-requests", json=change_body(), headers=viewer).status_code
        == 403
    )
    unknown = db_client.get(f"/api/v1/change-requests/{uuid.uuid4()}", headers=viewer)
    assert unknown.status_code == 404


def test_the_app_role_cannot_delete_governance_decisions(
    db_app: FastAPI, db_client: TestClient, people: dict[str, Any]
) -> None:
    request_exception(db_client, people["lead"]["h"])
    submit_change(db_client, people["lead"]["h"])
    for table in ("exceptions", "change_requests"):
        with db_app.state.session_factory() as db, pytest.raises(ProgrammingError):
            db.execute(text(f"DELETE FROM sentinel.{table}"))  # noqa: S608 - constant names
