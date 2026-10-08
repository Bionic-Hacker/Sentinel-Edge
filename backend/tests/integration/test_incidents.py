"""Incident management (Phase 7, spec §22): the workflow, who may make each move, evidence
linking rules, optimistic concurrency, and the tamper-evident timeline."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select, text
from sqlalchemy.exc import DBAPIError

from app.core.config import DbRole
from app.core.provenance import Provenance
from app.db.session import build_engine
from app.models.incident import IncidentStatus, Resolution
from app.models.security_event import (
    EventCategory,
    EventSource,
    Outcome,
    SecurityEvent,
    Severity,
)
from app.models.user import Role
from app.services import security_events
from app.services.incidents import moves_from
from app.services.security_events import EventContext
from tests.conftest import make_settings
from tests.helpers import audit_entries, bearer, create_user, session_token

pytestmark = [pytest.mark.security, pytest.mark.db]

S = IncidentStatus
WALK = [S.TRIAGED, S.INVESTIGATING, S.CONTAINMENT, S.REMEDIATION, S.VALIDATION]


@pytest.fixture
def people(db_app: FastAPI) -> dict[str, Any]:
    users = {
        "admin": create_user(
            db_app, "admin@example.com", role=Role.ADMIN, mfa_enabled=True, mfa_secret=b"x"
        ),
        "lead": create_user(
            db_app,
            "lead@example.com",
            role=Role.SECURITY_ENGINEER,
            mfa_enabled=True,
            mfa_secret=b"x",
        ),
        "analyst": create_user(db_app, "analyst@example.com", role=Role.ANALYST),
        "analyst2": create_user(db_app, "analyst2@example.com", role=Role.ANALYST),
        "viewer": create_user(db_app, "viewer@example.com", role=Role.VIEWER),
        "developer": create_user(db_app, "dev@example.com", role=Role.DEVELOPER),
    }
    return {
        name: {"user": user, "h": bearer(session_token(db_app, user))}
        for name, user in users.items()
    }


def event(
    app: FastAPI,
    *,
    provenance: Provenance = Provenance.LOCAL,
    category: EventCategory = EventCategory.SQL_INJECTION,
    severity: Severity = Severity.HIGH,
    ip: str = "203.0.113.5",
    outcome: Outcome = Outcome.REJECTED,
) -> uuid.UUID:
    with app.state.session_factory() as db:
        e = security_events.record_event(
            db,
            source=EventSource.HTTP_ANALYSIS,
            category=category,
            severity=severity,
            outcome=outcome,
            title="SQL injection probe",
            provenance=provenance,
            ctx=EventContext(
                source_ip=ip, method="POST", endpoint="/api/v1/auth/login", status_code=422
            ),
        )
        db.commit()
        return e.id


def create(client: TestClient, h: dict[str, str], **body: Any) -> Any:
    payload = {"title": "Suspicious activity", "severity": "high", **body}
    return client.post("/api/v1/incidents", json=payload, headers=h)


def move(
    client: TestClient, h: dict[str, str], incident: dict[str, Any], to: IncidentStatus, **body: Any
) -> Any:
    return client.post(
        f"/api/v1/incidents/{incident['id']}/transitions",
        json={"version": incident["version"], "to_status": to.value, **body},
        headers=h,
    )


def walk(client: TestClient, h: dict[str, str], incident: dict[str, Any]) -> dict[str, Any]:
    for status in WALK:
        response = move(client, h, incident, status)
        assert response.status_code == 200, response.text
        incident = response.json()
    return incident


def patch(client: TestClient, h: dict[str, str], incident: dict[str, Any], **body: Any) -> Any:
    return client.patch(
        f"/api/v1/incidents/{incident['id']}",
        json={"version": incident["version"], **body},
        headers=h,
    )


# --- Creating ---------------------------------------------------------------------------------


def test_analyst_opens_an_incident_from_events(
    db_app: FastAPI, db_client: TestClient, people: dict[str, Any]
) -> None:
    e1, e2 = event(db_app), event(db_app)
    response = create(db_client, people["analyst"]["h"], event_ids=[str(e1), str(e2)])
    assert response.status_code == 201, response.text
    incident = response.json()
    assert incident["reference"] == "INC-0001"
    assert incident["status"] == "DETECTED"
    assert incident["provenance"] == "LOCAL"
    assert incident["owner"]["display_name"] == "Analyst"
    assert incident["event_count"] == 2
    assert incident["source_ip"] == "203.0.113.5"
    assert [t["kind"] for t in incident["timeline"]] == ["created", "events_linked"]
    assert incident["integrity"] == {"verified": True, "entries_checked": 2, "first_mismatch": None}
    assert {e["incident_id"] for e in incident["events"]} == {incident["id"]}
    actions = [a.action for a in audit_entries(db_app) if a.resource_type == "incident"]
    assert actions == ["incident.created", "incident.events_linked"]


def test_simulated_and_real_evidence_never_mix(
    db_app: FastAPI, db_client: TestClient, people: dict[str, Any]
) -> None:
    real, sim = event(db_app), event(db_app, provenance=Provenance.SIMULATED)
    mixed = create(db_client, people["lead"]["h"], event_ids=[str(real), str(sim)])
    assert mixed.status_code == 422
    assert mixed.json()["error"]["code"] == "mixed_provenance"
    simulated = create(db_client, people["lead"]["h"], event_ids=[str(sim)]).json()
    assert simulated["provenance"] == "SIMULATED"
    link = db_client.post(
        f"/api/v1/incidents/{simulated['id']}/events",
        json={"version": simulated["version"], "event_ids": [str(real)]},
        headers=people["lead"]["h"],
    )
    assert link.status_code == 422


def test_an_event_is_evidence_for_one_incident(
    db_app: FastAPI, db_client: TestClient, people: dict[str, Any]
) -> None:
    e = event(db_app)
    assert create(db_client, people["lead"]["h"], event_ids=[str(e)]).status_code == 201
    again = create(db_client, people["lead"]["h"], event_ids=[str(e)])
    assert again.status_code == 409
    assert again.json()["error"]["code"] == "event_already_linked"
    unknown = create(db_client, people["lead"]["h"], event_ids=[str(uuid.uuid4())])
    assert unknown.status_code == 422


@pytest.mark.parametrize(
    "body",
    [
        {"title": "line\nbreak"},
        {"title": "   "},
        {"title": "x" * 161},
        {"summary": "bell\x07"},
        {"severity": "apocalyptic"},
        {"status": "CLOSED"},  # mass assignment
        {"owner_id": str(uuid.uuid4())},
    ],
)
def test_create_validates_input(db_client: TestClient, people: dict[str, Any], body: Any) -> None:
    assert create(db_client, people["analyst"]["h"], **body).status_code == 422


# --- The workflow -----------------------------------------------------------------------------


def test_full_lifecycle(db_app: FastAPI, db_client: TestClient, people: dict[str, Any]) -> None:
    analyst, lead = people["analyst"]["h"], people["lead"]["h"]
    incident = walk(db_client, analyst, create(db_client, analyst).json())
    assert incident["status"] == "VALIDATION"

    closing = {"resolution": "resolved", "note": "Validated: payload no longer accepted."}
    refused = move(db_client, analyst, incident, S.CLOSED, **closing)
    assert refused.status_code == 403  # closing is lead-only
    no_remediation = move(db_client, lead, incident, S.CLOSED, **closing)
    assert no_remediation.json()["error"]["code"] == "remediation_required"

    incident = patch(
        db_client, analyst, incident, remediation="Parameterized the query; added a WAF rule."
    ).json()
    closed = move(db_client, lead, incident, S.CLOSED, **closing)
    assert closed.status_code == 200, closed.text
    incident = closed.json()
    assert (incident["status"], incident["resolution"]) == ("CLOSED", "resolved")
    assert incident["closed_at"] is not None
    assert incident["integrity"]["verified"] is True
    statuses = [t["to_status"] for t in incident["timeline"] if t["kind"] == "status_changed"]
    assert statuses == [*[s.value for s in WALK], "CLOSED"]

    reopened = move(db_client, lead, incident, S.INVESTIGATING, note="New activity observed.")
    assert reopened.status_code == 200
    assert (reopened.json()["status"], reopened.json()["resolution"]) == ("INVESTIGATING", None)


@pytest.mark.parametrize(
    ("to", "body", "code"),
    [
        (S.CONTAINMENT, {}, "invalid_transition"),  # skipping steps
        (S.DETECTED, {}, "invalid_transition"),  # backwards
        (S.CLOSED, {"note": "n"}, "resolution_required"),
        (S.CLOSED, {"resolution": "false_positive"}, "note_required"),
        (S.CLOSED, {"resolution": "resolved", "note": "n"}, "resolution_not_available"),
        (S.TRIAGED, {"resolution": "duplicate"}, "unexpected_resolution"),
    ],
)
def test_transitions_follow_the_workflow(
    db_client: TestClient, people: dict[str, Any], to: IncidentStatus, body: Any, code: str
) -> None:
    lead = people["lead"]["h"]
    incident = create(db_client, lead).json()
    response = move(db_client, lead, incident, to, **body)
    assert response.status_code in (409, 422)
    assert response.json()["error"]["code"] == code


def test_early_close_as_false_positive(db_client: TestClient, people: dict[str, Any]) -> None:
    lead = people["lead"]["h"]
    incident = create(db_client, lead).json()
    closed = move(
        db_client, lead, incident, S.CLOSED, resolution="false_positive", note="Scanner test."
    )
    assert closed.status_code == 200
    assert closed.json()["resolution"] == "false_positive"


def test_failed_validation_returns_to_remediation(
    db_client: TestClient, people: dict[str, Any]
) -> None:
    analyst = people["analyst"]["h"]
    incident = walk(db_client, analyst, create(db_client, analyst).json())
    assert (
        move(db_client, analyst, incident, S.REMEDIATION).json()["error"]["code"] == "note_required"
    )
    back = move(db_client, analyst, incident, S.REMEDIATION, note="Payload still accepted.")
    assert back.json()["status"] == "REMEDIATION"


def test_workflow_table_is_complete() -> None:
    """Every open status can go forward one step and be closed early; only VALIDATION closes
    as resolved; CLOSED can only be reopened."""
    for status in S:
        targets = {m.to_status for m in moves_from(status)}
        if status is S.CLOSED:
            assert targets == {S.INVESTIGATING}
        elif status is S.VALIDATION:
            assert targets == {S.CLOSED, S.REMEDIATION}
        else:
            assert S.CLOSED in targets
            assert len(targets) == 2
    validated = {r for m in moves_from(S.VALIDATION) for r in m.resolutions}
    early = {r for m in moves_from(S.DETECTED) for r in m.resolutions}
    assert validated == set(Resolution)
    assert early == {Resolution.FALSE_POSITIVE, Resolution.DUPLICATE}


# --- Who may do what --------------------------------------------------------------------------


def test_analysts_cannot_work_someone_elses_incident(
    db_app: FastAPI, db_client: TestClient, people: dict[str, Any]
) -> None:
    mine = create(db_client, people["analyst"]["h"]).json()
    other = people["analyst2"]["h"]
    attempts = [
        move(db_client, other, mine, S.TRIAGED),
        patch(db_client, other, mine, title="Hijacked"),
        db_client.post(
            f"/api/v1/incidents/{mine['id']}/events",
            json={"version": 1, "event_ids": [str(event(db_app))]},
            headers=other,
        ),
        db_client.post(
            f"/api/v1/incidents/{mine['id']}/assignment",
            json={"version": 1, "owner_id": str(people["analyst2"]["user"].id)},
            headers=other,
        ),
    ]
    assert [r.status_code for r in attempts] == [403, 403, 403, 403]
    denials = audit_entries(db_app, "authz.denied")
    assert len(denials) == 4
    assert {d.resource_type for d in denials} == {"incident"}
    with db_app.state.session_factory() as db:
        bola = db.scalars(
            select(SecurityEvent).where(SecurityEvent.category == EventCategory.BOLA)
        ).all()
    assert bola[0].title == "Attempt to act on an incident assigned to someone else"


def test_notes_are_open_to_every_investigator(
    db_client: TestClient, people: dict[str, Any]
) -> None:
    incident = create(db_client, people["analyst"]["h"]).json()
    note = db_client.post(
        f"/api/v1/incidents/{incident['id']}/notes",
        json={"body": "Seen the same address in the WAF logs.\nTwo lines."},
        headers=people["analyst2"]["h"],
    )
    assert note.status_code == 201
    entry = note.json()["timeline"][-1]
    assert (entry["kind"], entry["actor_label"]) == ("note", "analyst2@example.com")


def test_analyst_triages_an_unassigned_detection_and_owns_it(
    db_app: FastAPI, db_client: TestClient, people: dict[str, Any]
) -> None:
    event(db_app, severity=Severity.CRITICAL)  # opens an incident automatically
    (summary,) = db_client.get("/api/v1/incidents", headers=people["analyst"]["h"]).json()["items"]
    assert summary["owner"] is None
    incident = db_client.get(
        f"/api/v1/incidents/{summary['id']}", headers=people["analyst"]["h"]
    ).json()
    assert [m["to_status"] for m in incident["permissions"]["moves"]] == ["TRIAGED"]
    triaged = move(db_client, people["analyst"]["h"], incident, S.TRIAGED)
    assert triaged.status_code == 200, triaged.text
    assert triaged.json()["owner"]["display_name"] == "Analyst"
    kinds = [t["kind"] for t in triaged.json()["timeline"]]
    assert kinds[-2:] == ["assigned", "status_changed"]


def test_assignment_rules(db_client: TestClient, people: dict[str, Any]) -> None:
    lead_h = people["lead"]["h"]
    incident = create(db_client, lead_h).json()
    unassign = db_client.post(
        f"/api/v1/incidents/{incident['id']}/assignment",
        json={"version": incident["version"], "owner_id": None},
        headers=lead_h,
    ).json()
    take = db_client.post(
        f"/api/v1/incidents/{incident['id']}/assignment",
        json={"version": unassign["version"], "owner_id": str(people["analyst"]["user"].id)},
        headers=people["analyst"]["h"],
    )
    assert take.status_code == 200
    taken = take.json()
    for target, code in (("viewer", 422), ("developer", 422), ("analyst2", 200)):
        response = db_client.post(
            f"/api/v1/incidents/{incident['id']}/assignment",
            json={"version": taken["version"], "owner_id": str(people[target]["user"].id)},
            headers=lead_h,
        )
        assert response.status_code == code, (target, response.text)
    assignees = db_client.get("/api/v1/incidents/assignees", headers=lead_h).json()["items"]
    assert {a["role"] for a in assignees} == {"ADMIN", "SECURITY_ENGINEER", "ANALYST"}


def test_severity_is_changed_only_by_leads(db_client: TestClient, people: dict[str, Any]) -> None:
    incident = create(db_client, people["analyst"]["h"]).json()
    assert patch(db_client, people["analyst"]["h"], incident, severity="low").status_code == 403
    changed = patch(db_client, people["lead"]["h"], incident, severity="critical")
    assert changed.json()["severity"] == "critical"
    assert changed.json()["timeline"][-1]["details"]["severity"] == "high -> critical"


def test_viewers_read_but_never_write(db_client: TestClient, people: dict[str, Any]) -> None:
    incident = create(db_client, people["lead"]["h"]).json()
    viewer = people["viewer"]["h"]
    detail = db_client.get(f"/api/v1/incidents/{incident['id']}", headers=viewer).json()
    assert detail["permissions"]["moves"] == []
    assert detail["permissions"]["can_add_note"] is False
    note = db_client.post(
        f"/api/v1/incidents/{incident['id']}/notes", json={"body": "x"}, headers=viewer
    )
    assert note.status_code == 403


def test_closed_incidents_are_read_only_except_notes(
    db_client: TestClient, people: dict[str, Any]
) -> None:
    lead = people["lead"]["h"]
    incident = create(db_client, lead).json()
    incident = move(
        db_client, lead, incident, S.CLOSED, resolution="duplicate", note="INC-1"
    ).json()
    assert (
        patch(db_client, lead, incident, title="New").json()["error"]["code"] == "incident_closed"
    )
    note = db_client.post(
        f"/api/v1/incidents/{incident['id']}/notes",
        json={"body": "Post-incident review done."},
        headers=lead,
    )
    assert note.status_code == 201


# --- Concurrency and integrity ----------------------------------------------------------------


def test_stale_writes_are_refused(db_client: TestClient, people: dict[str, Any]) -> None:
    lead = people["lead"]["h"]
    incident = create(db_client, lead).json()
    assert patch(db_client, lead, incident, title="First").status_code == 200
    stale = patch(db_client, lead, incident, title="Second")
    assert stale.status_code == 409
    assert stale.json()["error"]["code"] == "stale_version"


@pytest.fixture
def owner_engine(migrator_engine: Engine) -> Engine:
    return migrator_engine


def test_tampering_with_the_timeline_is_detected(
    db_client: TestClient, people: dict[str, Any], owner_engine: Engine
) -> None:
    lead = people["lead"]["h"]
    incident = create(db_client, lead).json()
    note = db_client.post(
        f"/api/v1/incidents/{incident['id']}/notes", json={"body": "Original note"}, headers=lead
    ).json()["timeline"][-1]
    # Someone with table-owner rights edits the note directly in the database.
    with owner_engine.begin() as conn:
        conn.execute(
            text("UPDATE sentinel.incident_timeline SET body = 'Rewritten' WHERE id = :id"),
            {"id": note["id"]},
        )
    detail = db_client.get(f"/api/v1/incidents/{incident['id']}", headers=lead).json()
    assert detail["integrity"]["verified"] is False
    assert detail["integrity"]["first_mismatch"] == note["id"]


def test_deleting_a_timeline_entry_is_detected(
    db_client: TestClient, people: dict[str, Any], owner_engine: Engine
) -> None:
    lead = people["lead"]["h"]
    incident = create(db_client, lead).json()
    created = incident["timeline"][0]
    with owner_engine.begin() as conn:
        conn.execute(
            text("DELETE FROM sentinel.incident_timeline WHERE id = :id"), {"id": created["id"]}
        )
    detail = db_client.get(f"/api/v1/incidents/{incident['id']}", headers=lead).json()
    assert detail["integrity"] == {
        "verified": False,
        "entries_checked": 0,
        "first_mismatch": created["id"],
    }


@pytest.fixture
def app_engine(migrator_engine: Engine) -> Iterator[Engine]:
    engine = build_engine(make_settings(), DbRole.APP)
    yield engine
    engine.dispose()


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE sentinel.incident_timeline SET body = 'x'",
        "DELETE FROM sentinel.incident_timeline",
        "DELETE FROM sentinel.incidents",
        "UPDATE sentinel.security_events SET severity = 'info'",
    ],
)
def test_app_role_cannot_rewrite_incident_records(
    db_client: TestClient, people: dict[str, Any], app_engine: Engine, statement: str
) -> None:
    create(db_client, people["lead"]["h"])
    with app_engine.connect() as conn, pytest.raises(DBAPIError) as excinfo:
        conn.execute(text(statement))
    assert "permission denied" in str(excinfo.value).lower()


def test_evidence_links_are_write_once(
    db_app: FastAPI, db_client: TestClient, people: dict[str, Any], app_engine: Engine
) -> None:
    e = event(db_app)
    first = create(db_client, people["lead"]["h"], event_ids=[str(e)]).json()
    second = create(db_client, people["lead"]["h"]).json()
    for statement, params in (
        (
            "UPDATE sentinel.security_events SET incident_id = :other WHERE id = :e",
            {"other": second["id"]},
        ),
        ("UPDATE sentinel.security_events SET incident_id = NULL WHERE id = :e", {}),
    ):
        with app_engine.connect() as conn, pytest.raises(DBAPIError) as excinfo:
            conn.execute(text(statement), {"e": str(e), **params})
        assert "already evidence" in str(excinfo.value)
    assert first["event_count"] == 1


def test_deleting_the_owner_unassigns_the_incident(
    db_client: TestClient, people: dict[str, Any]
) -> None:
    incident = create(db_client, people["analyst2"]["h"]).json()
    gone = db_client.delete(
        f"/api/v1/users/{people['analyst2']['user'].id}", headers=people["admin"]["h"]
    )
    assert gone.status_code == 204
    detail = db_client.get(
        f"/api/v1/incidents/{incident['id']}", headers=people["lead"]["h"]
    ).json()
    assert detail["owner"] is None
    assert detail["timeline"][0]["actor_label"] == "analyst2@example.com"  # history kept


# --- Listing and scoring ----------------------------------------------------------------------


def test_listing_filters_and_pages(
    db_app: FastAPI, db_client: TestClient, people: dict[str, Any]
) -> None:
    lead = people["lead"]["h"]
    for i in range(3):
        create(db_client, people["analyst"]["h"], title=f"Live {i}")
    create(db_client, lead, event_ids=[str(event(db_app, provenance=Provenance.SIMULATED))])
    closed = create(db_client, lead).json()
    move(db_client, lead, closed, S.CLOSED, resolution="duplicate", note="dup")

    def titles(**params: Any) -> list[str]:
        page = db_client.get("/api/v1/incidents", params=params, headers=lead).json()
        return [i["title"] for i in page["items"]]

    assert len(titles(view="live")) == 3  # open by default
    assert len(titles(view="simulated")) == 1
    assert len(titles(state="closed")) == 1
    assert len(titles(state="all")) == 5
    assert len(titles(owner="me")) == 1  # the simulated one the lead opened
    analyst_mine = db_client.get(
        "/api/v1/incidents", params={"owner": "me"}, headers=people["analyst"]["h"]
    ).json()
    assert len(analyst_mine["items"]) == 3
    first = db_client.get(
        "/api/v1/incidents", params={"limit": 2, "state": "all"}, headers=lead
    ).json()
    rest = db_client.get(
        "/api/v1/incidents",
        params={"limit": 10, "state": "all", "before_number": first["next_before_number"]},
        headers=lead,
    ).json()
    assert len(first["items"]) + len(rest["items"]) == 5
    assert (
        db_client.get("/api/v1/incidents", params={"state": "bogus"}, headers=lead).status_code
        == 422
    )


def test_risk_score_is_explained(
    db_app: FastAPI, db_client: TestClient, people: dict[str, Any]
) -> None:
    e = event(db_app, outcome=Outcome.ALLOWED)
    incident = create(db_client, people["lead"]["h"], event_ids=[str(e)]).json()
    risk = incident["risk"]
    assert [f["points"] for f in risk["factors"]] == [75, 10, 5]
    assert risk["score"] == 90
    assert "POST /api/v1/auth/login" in risk["factors"][2]["reason"]


def test_unknown_incident_is_404(db_client: TestClient, people: dict[str, Any]) -> None:
    response = db_client.get(f"/api/v1/incidents/{uuid.uuid4()}", headers=people["lead"]["h"])
    assert response.status_code == 404
