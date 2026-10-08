"""Protected application inventory (Phase 7, spec §40): who sees which application, how they
are registered and changed, and that unavailable values say why instead of inventing them."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.api_policy import ENDPOINTS
from app.models.user import Role
from tests.helpers import audit_entries, bearer, create_user, session_token

pytestmark = [pytest.mark.security, pytest.mark.db]


@pytest.fixture
def people(db_app: FastAPI) -> dict[str, Any]:
    specs = {
        "admin": Role.ADMIN,
        "lead": Role.SECURITY_ENGINEER,
        "analyst": Role.ANALYST,
        "viewer": Role.VIEWER,
        "dev": Role.DEVELOPER,
        "dev2": Role.DEVELOPER,
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


def register(client: TestClient, h: dict[str, str], **body: Any) -> Any:
    payload = {
        "slug": "payments-api",
        "name": "Payments API",
        "environment": "production",
        "criticality": "critical",
        "domain": "payments.corp.example",
        **body,
    }
    return client.post("/api/v1/applications", json=payload, headers=h)


def test_sentineledge_is_the_first_protected_application(
    db_client: TestClient, people: dict[str, Any]
) -> None:
    (platform,) = db_client.get("/api/v1/applications", headers=people["viewer"]["h"]).json()[
        "items"
    ]
    assert (platform["slug"], platform["is_platform"]) == ("sentineledge", True)
    assert platform["api_count"] == {
        "status": "measured",
        "value": len(ENDPOINTS),
        "note": "Endpoints in the live route table (API Security Center).",
    }
    assert platform["waf_status"]["status"] == "planned"
    assert "Phase 5" in platform["waf_status"]["note"]
    assert platform["vulnerability_count"]["status"] == "not_connected"  # until a scan import
    assert "make scan-import" in platform["last_scan"]["note"]
    assert platform["security_score"]["value"] is None


def test_registering_an_application(
    db_app: FastAPI, db_client: TestClient, people: dict[str, Any]
) -> None:
    created = register(db_client, people["lead"]["h"], owner_id=str(people["dev"]["user"].id))
    assert created.status_code == 201, created.text
    app = created.json()
    assert app["owner"]["display_name"] == "Dev"
    assert app["status"] == "active"
    assert app["api_count"]["status"] == "not_connected"  # no telemetry for other apps yet
    assert register(db_client, people["lead"]["h"]).status_code == 409  # slug in use
    (record,) = audit_entries(db_app, "application.created")
    assert record.details["slug"] == "payments-api"


@pytest.mark.parametrize(
    "body",
    [
        {"domain": "https://payments.corp.example"},
        {"domain": "payments.corp.example:8443"},
        {"domain": "user:pass@corp.example"},
        {"domain": "-bad-.example"},
        {"slug": "Payments API"},
        {"name": "two\nlines"},
        {"criticality": "extreme"},
        {"is_platform": True},  # mass assignment
        {"status": "retired"},
    ],
)
def test_registration_is_validated(
    db_client: TestClient, people: dict[str, Any], body: dict[str, Any]
) -> None:
    assert register(db_client, people["lead"]["h"], **body).status_code == 422


def test_owners_must_hold_an_owner_role(db_client: TestClient, people: dict[str, Any]) -> None:
    for name, code in (("analyst", 422), ("viewer", 422), ("dev", 201)):
        response = register(
            db_client,
            people["lead"]["h"],
            slug=f"app-{name}",
            owner_id=str(people[name]["user"].id),
        )
        assert response.status_code == code, (name, response.text)


def test_developers_see_only_their_own_applications(
    db_app: FastAPI, db_client: TestClient, people: dict[str, Any]
) -> None:
    mine = register(db_client, people["lead"]["h"], owner_id=str(people["dev"]["user"].id)).json()
    theirs = register(
        db_client, people["lead"]["h"], slug="hr-portal", owner_id=str(people["dev2"]["user"].id)
    ).json()
    listing = db_client.get("/api/v1/applications", headers=people["dev"]["h"]).json()["items"]
    assert [a["slug"] for a in listing] == ["payments-api"]
    assert (
        db_client.get(f"/api/v1/applications/{mine['id']}", headers=people["dev"]["h"]).status_code
        == 200
    )
    other = db_client.get(f"/api/v1/applications/{theirs['id']}", headers=people["dev"]["h"])
    missing = db_client.get(f"/api/v1/applications/{uuid.uuid4()}", headers=people["dev"]["h"])
    assert other.status_code == missing.status_code == 404  # existence is not revealed
    (denied,) = audit_entries(db_app, "authz.denied")
    assert (denied.resource_type, denied.resource_id) == ("application", theirs["id"])
    everyone = db_client.get("/api/v1/applications", headers=people["analyst"]["h"]).json()
    assert len(everyone["items"]) == 3


def test_updating_an_application(
    db_app: FastAPI, db_client: TestClient, people: dict[str, Any]
) -> None:
    app = register(db_client, people["lead"]["h"], owner_id=str(people["dev"]["user"].id)).json()
    url = f"/api/v1/applications/{app['id']}"
    changed = db_client.patch(
        url,
        json={"version": app["version"], "criticality": "high", "clear_owner": True},
        headers=people["admin"]["h"],
    )
    assert changed.status_code == 200, changed.text
    assert (changed.json()["criticality"], changed.json()["owner"]) == ("high", None)
    stale = db_client.patch(
        url, json={"version": app["version"], "name": "Renamed"}, headers=people["admin"]["h"]
    )
    assert stale.status_code == 409
    retired = db_client.patch(
        url,
        json={"version": changed.json()["version"], "status": "retired"},
        headers=people["admin"]["h"],
    )
    assert retired.json()["status"] == "retired"
    (update, _) = audit_entries(db_app, "application.updated")
    assert update.details["after"] == {"criticality": "high", "owner_id": "None"}


def test_sentineledge_itself_cannot_be_retired(
    db_client: TestClient, people: dict[str, Any]
) -> None:
    (platform,) = db_client.get("/api/v1/applications", headers=people["lead"]["h"]).json()["items"]
    response = db_client.patch(
        f"/api/v1/applications/{platform['id']}",
        json={"version": platform["version"], "status": "retired"},
        headers=people["lead"]["h"],
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "platform_application"


def test_owner_cannot_be_set_and_cleared_at_once(
    db_client: TestClient, people: dict[str, Any]
) -> None:
    app = register(db_client, people["lead"]["h"]).json()
    response = db_client.patch(
        f"/api/v1/applications/{app['id']}",
        json={"version": 1, "owner_id": str(people["dev"]["user"].id), "clear_owner": True},
        headers=people["lead"]["h"],
    )
    assert response.status_code == 422


def test_owner_candidates_are_listed_for_editors(
    db_client: TestClient, people: dict[str, Any]
) -> None:
    owners = db_client.get("/api/v1/applications/owners", headers=people["lead"]["h"]).json()
    assert {o["role"] for o in owners["items"]} == {"ADMIN", "SECURITY_ENGINEER", "DEVELOPER"}
    assert all(set(o) == {"id", "display_name", "role"} for o in owners["items"])
