"""Threat modeling and the control catalogue (Phase 10, ADR-0022): the catalogue is loaded
once and kept read-only, application models are edited by leads only, every change is audited,
and developers see only their own applications' models."""

from __future__ import annotations

import copy
import threading
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.exc import ProgrammingError

from app.models.governance import Control, ModelOrigin, Threat, ThreatModel
from app.models.user import Role
from app.services.governance import load_catalogue, sync_catalogue
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


def catalogue_model(client: TestClient, h: dict[str, str]) -> dict[str, Any]:
    items = client.get("/api/v1/threat-models", headers=h).json()["items"]
    (model,) = [m for m in items if m["origin"] == "catalogue"]
    detail: dict[str, Any] = client.get(f"/api/v1/threat-models/{model['id']}", headers=h).json()
    return detail


def register(client: TestClient, h: dict[str, str], slug: str = "payments-api") -> dict[str, Any]:
    response = client.post(
        "/api/v1/applications",
        json={
            "slug": slug,
            "name": slug.replace("-", " ").title(),
            "environment": "production",
            "criticality": "critical",
            "domain": f"{slug}.corp.example",
        },
        headers=h,
    )
    assert response.status_code == 201, response.text
    app: dict[str, Any] = response.json()
    return app


def new_model(
    client: TestClient, h: dict[str, str], app_id: str, method: str = "stride"
) -> dict[str, Any]:
    response = client.post(
        "/api/v1/threat-models",
        json={"application_id": app_id, "name": "Payments", "method": method, "scope": "API"},
        headers=h,
    )
    assert response.status_code == 201, response.text
    model: dict[str, Any] = response.json()
    return model


# --- the catalogue ----------------------------------------------------------------------------


def test_the_catalogue_is_loaded_once_on_first_use(
    db_app: FastAPI, db_client: TestClient, people: dict[str, Any]
) -> None:
    cat = load_catalogue()
    controls = db_client.get("/api/v1/governance/controls", headers=people["viewer"]["h"]).json()
    assert len(controls["items"]) == len(cat["controls"])
    assert controls["catalogue_digest"] == cat["digest"]
    assert controls["counts"]["implemented"] + controls["counts"]["planned"] == len(cat["controls"])

    model = catalogue_model(db_client, people["viewer"]["h"])
    assert model["version_label"] == cat["model"]["version"]
    assert len(model["threats"]) == len(cat["model"]["threats"])
    assert model["permissions"] == {
        "can_edit": False,
        "maintained_as_code": True,
        "can_archive": False,
        "can_delete": False,
    }
    t_id_01 = next(t for t in model["threats"] if t["ref"] == "T-ID-01")
    assert t_id_01["risk"] == 9
    assert {c["ref"] for c in t_id_01["controls"]} >= {"C-ID-04", "C-ID-05", "C-API-03"}
    assert model["stats"]["unmapped"] == []

    db_client.get("/api/v1/governance/requirements", headers=people["viewer"]["h"])
    (synced,) = audit_entries(db_app, "governance.catalogue_synced")
    assert synced.actor_label == "system:governance"
    assert synced.details["digest"] == cat["digest"]


def test_controls_cite_the_threats_they_mitigate_and_filter(
    db_client: TestClient, people: dict[str, Any]
) -> None:
    h = people["dev"]["h"]
    items = db_client.get("/api/v1/governance/controls", headers=h).json()["items"]
    by_ref = {c["ref"]: c for c in items}
    assert "T-ID-01" in by_ref["C-ID-05"]["threats"]
    assert by_ref["C-API-01"]["extensions"][0]["phase"] == 7
    assert {"kind": "test", "ref": "test_users_can_read_only_their_own_record"} in by_ref[
        "C-API-01"
    ]["evidence"]

    planned = db_client.get("/api/v1/governance/controls?status=planned", headers=h).json()
    assert planned["items"]
    assert all(c["status"] == "planned" for c in planned["items"])
    waf = db_client.get("/api/v1/governance/controls?family=WAF", headers=h).json()["items"]
    assert {c["ref"] for c in waf} == {"C-WAF-01", "C-WAF-02", "C-WAF-03", "C-WAF-04"}
    found = db_client.get("/api/v1/governance/controls?q=argon2id", headers=h).json()["items"]
    assert [c["ref"] for c in found] == ["C-ID-01"]
    bad = db_client.get("/api/v1/governance/controls?family=waf;drop", headers=h)
    assert bad.status_code == 422


def test_requirements_trace_to_threats_and_controls(
    db_client: TestClient, people: dict[str, Any]
) -> None:
    items = db_client.get("/api/v1/governance/requirements", headers=people["analyst"]["h"]).json()[
        "items"
    ]
    sqli = next(r for r in items if r["title"] == "SQL injection")
    assert [t["ref"] for t in sqli["threats"]] == ["T-API-07"]
    assert "C-SO-02" in sqli["controls"]
    assert sqli["evidence"]


def test_a_new_catalogue_updates_retires_and_relinks(db_app: FastAPI) -> None:
    cat = copy.deepcopy(load_catalogue())
    with db_app.state.session_factory() as db:
        assert sync_catalogue(db, cat) is True
        db.commit()
        assert sync_catalogue(db, cat) is False  # same digest: nothing to do

        changed = copy.deepcopy(cat)
        changed["digest"] = "0" * 64
        changed["controls"] = [c for c in changed["controls"] if c["ref"] != "C-WAF-02"]
        threats = changed["model"]["threats"]
        changed["model"]["threats"] = [t for t in threats if t["ref"] != "T-INP-01"]
        edge = next(t for t in changed["model"]["threats"] if t["ref"] == "T-EDGE-05")
        edge["controls"] = ["C-API-07", "C-WEB-01"]
        edge["status"] = "partly_mitigated"
        assert sync_catalogue(db, changed) is True
        db.commit()

        assert db.scalar(select(Control.retired).where(Control.ref == "C-WAF-02")) is True
        retired = db.scalar(select(Threat).where(Threat.ref == "T-INP-01"))
        assert retired is not None
        assert retired.retired is True
        model = db.scalar(select(ThreatModel).where(ThreatModel.origin == ModelOrigin.CATALOGUE))
        assert model is not None
        assert model.catalogue_digest == "0" * 64
    assert len(audit_entries(db_app, "governance.catalogue_synced")) == 2


def test_concurrent_first_requests_load_the_catalogue_once(
    db_app: FastAPI, db_client: TestClient, people: dict[str, Any]
) -> None:
    results: list[int] = []
    barrier = threading.Barrier(8)

    def read() -> None:
        barrier.wait()
        r = db_client.get("/api/v1/governance/controls", headers=people["viewer"]["h"])
        results.append(r.status_code)

    threads = [threading.Thread(target=read) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results == [200] * 8
    assert len(audit_entries(db_app, "governance.catalogue_synced")) == 1


def test_sentineledge_s_own_model_is_maintained_as_code(
    db_client: TestClient, people: dict[str, Any]
) -> None:
    h = people["admin"]["h"]
    model = catalogue_model(db_client, h)
    url = f"/api/v1/threat-models/{model['id']}"
    attempts = [
        db_client.patch(url, json={"version": model["version"], "name": "Mine"}, headers=h),
        db_client.post(f"{url}/elements", json={"kind": "asset", "name": "X"}, headers=h),
        db_client.post(
            f"{url}/threats",
            json={"title": "X", "stride": "S", "likelihood": 1, "impact": 1},
            headers=h,
        ),
        db_client.patch(
            f"{url}/threats/{model['threats'][0]['id']}",
            json={"version": model["threats"][0]["version"], "status": "closed"},
            headers=h,
        ),
    ]
    for response in attempts:
        assert response.status_code == 409, response.text
        assert response.json()["error"]["code"] == "maintained_as_code"


# --- application models -----------------------------------------------------------------------


def test_a_lead_builds_a_stride_model(
    db_app: FastAPI, db_client: TestClient, people: dict[str, Any]
) -> None:
    h = people["lead"]["h"]
    app = register(db_client, people["admin"]["h"])
    model = new_model(db_client, h, app["id"])
    assert (model["reference"], model["status"], model["origin"]) == ("TM-0002", "draft", "app")
    assert model["permissions"] == {
        "can_edit": True,
        "maintained_as_code": False,
        "can_archive": True,
        "can_delete": True,
    }
    url = f"/api/v1/threat-models/{model['id']}"

    for kind, name in (("boundary", "Internet to API"), ("asset", "Card tokens")):
        r = db_client.post(f"{url}/elements", json={"kind": kind, "name": name}, headers=h)
        assert r.status_code == 201, r.text
    flow = db_client.post(
        f"{url}/elements",
        json={"kind": "flow", "name": "Browser → API", "boundaries": ["TB1"]},
        headers=h,
    ).json()
    refs = {(e["kind"], e["ref"]) for e in flow["elements"]}
    assert refs == {("boundary", "TB1"), ("asset", "A1"), ("flow", "F1")}
    assert next(e for e in flow["elements"] if e["ref"] == "F1")["boundaries"] == ["TB1"]

    threat = db_client.post(
        f"{url}/threats",
        json={
            "title": "Card data exfiltrated through an injection",
            "stride": "I/T",
            "owasp": "API8",
            "boundaries": ["TB1"],
            "likelihood": 2,
            "impact": 3,
            "status": "open",
            "controls": ["C-API-04", "C-WAF-01"],
        },
        headers=h,
    )
    assert threat.status_code == 201, threat.text
    detail = threat.json()
    (t,) = detail["threats"]
    assert (t["ref"], t["risk"]) == ("TH-001", 6)
    assert [c["ref"] for c in t["controls"]] == ["C-API-04", "C-WAF-01"]
    assert detail["stats"]["by_stride"] == {"I": 1, "T": 1}
    cell = next(c for c in detail["stats"]["matrix"] if (c["likelihood"], c["impact"]) == (2, 3))
    assert cell["count"] == 1

    planned_only = db_client.post(
        f"{url}/threats",
        json={
            "title": "Edge flood",
            "stride": "D",
            "likelihood": 2,
            "impact": 2,
            "controls": ["C-WAF-03"],
        },
        headers=h,
    ).json()
    assert planned_only["stats"]["only_planned_controls"] == ["TH-002"]

    mitigated = db_client.patch(
        f"{url}/threats/{t['id']}",
        json={"version": t["version"], "status": "mitigated", "controls": ["C-API-04"]},
        headers=h,
    )
    assert mitigated.status_code == 200, mitigated.text
    assert mitigated.json()["threats"][0]["controls"][0]["ref"] == "C-API-04"
    stale = db_client.patch(
        f"{url}/threats/{t['id']}", json={"version": t["version"], "impact": 1}, headers=h
    )
    assert stale.status_code == 409
    assert stale.json()["error"]["code"] == "stale_version"

    summary = next(
        m
        for m in db_client.get("/api/v1/threat-models", headers=h).json()["items"]
        if m["id"] == model["id"]
    )
    assert summary["threat_count"] == 2
    assert summary["highest_open_risk"] == 4  # the open 2x3 is now mitigated; the 2x2 remains

    actions = [e.action for e in audit_entries(db_app) if e.action.startswith("threat_model.")]
    assert actions == [
        "threat_model.created",
        "threat_model.element_added",
        "threat_model.element_added",
        "threat_model.element_added",
        "threat_model.threat_added",
        "threat_model.threat_added",
        "threat_model.threat_updated",
    ]
    update = audit_entries(db_app, "threat_model.threat_updated")[0]
    assert update.details["changes"]["controls"] == [["C-API-04", "C-WAF-01"], ["C-API-04"]]


def test_threats_must_cite_real_controls_and_boundaries(
    db_client: TestClient, people: dict[str, Any]
) -> None:
    h = people["admin"]["h"]
    model = new_model(db_client, h, register(db_client, h)["id"])
    url = f"/api/v1/threat-models/{model['id']}"
    base = {"title": "X", "stride": "S", "likelihood": 1, "impact": 1}
    cases = [
        ({**base, "controls": ["C-NOPE-01"]}, 422, "unknown_control"),
        ({**base, "boundaries": ["TB9"]}, 422, "unknown_boundary"),
        ({**base, "stride": "X"}, 422, None),
        ({**base, "likelihood": 4}, 422, None),
        ({**base, "admin": True}, 422, None),
    ]
    for body, status, code in cases:
        r = db_client.post(f"{url}/threats", json=body, headers=h)
        assert r.status_code == status, (body, r.text)
        if code:
            assert r.json()["error"]["code"] == code
    asset = db_client.post(
        f"{url}/elements", json={"kind": "asset", "name": "X", "boundaries": ["TB1"]}, headers=h
    )
    assert asset.status_code == 422
    assert asset.json()["error"]["code"] == "boundaries_not_allowed"


def test_a_pasta_model_records_its_stages(db_client: TestClient, people: dict[str, Any]) -> None:
    h = people["lead"]["h"]
    app = register(db_client, people["admin"]["h"])
    pasta = new_model(db_client, h, app["id"], method="pasta")
    assert set(pasta["pasta"]) == {
        "objectives",
        "technical_scope",
        "decomposition",
        "threat_analysis",
        "vulnerability_analysis",
        "attack_modeling",
        "risk_impact",
    }
    url = f"/api/v1/threat-models/{pasta['id']}"
    done = db_client.patch(
        url,
        json={
            "version": pasta["version"],
            "pasta": {"objectives": "Keep card data private."},
            "status": "active",
        },
        headers=h,
    )
    assert done.status_code == 200, done.text
    assert done.json()["pasta"]["objectives"] == "Keep card data private."
    assert done.json()["status"] == "active"
    unknown = db_client.patch(
        url, json={"version": done.json()["version"], "pasta": {"stage8": "x"}}, headers=h
    )
    assert unknown.status_code == 422

    stride = new_model(db_client, h, app["id"])
    not_pasta = db_client.patch(
        f"/api/v1/threat-models/{stride['id']}",
        json={"version": stride["version"], "pasta": {"objectives": "x"}},
        headers=h,
    )
    assert not_pasta.status_code == 422
    assert not_pasta.json()["error"]["code"] == "not_pasta"


def test_elements_are_retired_not_deleted(db_client: TestClient, people: dict[str, Any]) -> None:
    h = people["admin"]["h"]
    model = new_model(db_client, h, register(db_client, h)["id"])
    url = f"/api/v1/threat-models/{model['id']}"
    added = db_client.post(f"{url}/elements", json={"kind": "asset", "name": "Old"}, headers=h)
    element = added.json()["elements"][0]
    retired = db_client.patch(
        f"{url}/elements/{element['id']}", json={"retired": True}, headers=h
    ).json()
    assert retired["elements"][0]["retired"] is True
    other = new_model(db_client, h, register(db_client, h, "other-app")["id"])
    wrong = db_client.patch(
        f"/api/v1/threat-models/{other['id']}/elements/{element['id']}",
        json={"name": "x"},
        headers=h,
    )
    assert wrong.status_code == 404


def test_developers_see_only_their_own_applications_models(
    db_app: FastAPI, db_client: TestClient, people: dict[str, Any]
) -> None:
    admin, dev = people["admin"]["h"], people["dev"]["h"]
    theirs = register(db_client, admin, "dev-app")
    mine = new_model(db_client, admin, theirs["id"])
    owned = db_client.patch(
        f"/api/v1/applications/{theirs['id']}",
        json={"owner_id": str(people["dev"]["user"].id), "version": theirs["version"]},
        headers=admin,
    )
    assert owned.status_code == 200, owned.text
    other = new_model(db_client, admin, register(db_client, admin, "other-app")["id"])

    listed = db_client.get("/api/v1/threat-models", headers=dev).json()["items"]
    assert [m["id"] for m in listed] == [mine["id"]]
    seen = db_client.get(f"/api/v1/threat-models/{mine['id']}", headers=dev).json()
    assert seen["permissions"] == {
        "can_edit": False,
        "maintained_as_code": False,
        "can_archive": True,
        "can_delete": False,
    }
    denied = db_client.get(f"/api/v1/threat-models/{other['id']}", headers=dev)
    assert denied.status_code == 404
    assert audit_entries(db_app, "authz.denied")[-1].resource_type == "threat_model"

    # A developer archives their own application's model, never another's, and cannot delete.
    others = db_client.post(
        f"/api/v1/threat-models/{other['id']}/archive", json={"version": 1}, headers=dev
    )
    assert others.status_code == 404
    assert db_client.delete(f"/api/v1/threat-models/{mine['id']}", headers=dev).status_code == 403
    archived = db_client.post(
        f"/api/v1/threat-models/{mine['id']}/archive",
        json={"version": seen["version"]},
        headers=dev,
    )
    assert archived.status_code == 200, archived.text
    assert archived.json()["status"] == "archived"
    assert archived.json()["permissions"]["can_archive"] is False
    (entry,) = audit_entries(db_app, "threat_model.archived")
    assert entry.details["before"] == "draft"

    everyone = db_client.get("/api/v1/threat-models", headers=people["viewer"]["h"]).json()
    assert len(everyone["items"]) == 3  # the catalogue model and both application models


def test_a_model_needs_an_active_application(db_client: TestClient, people: dict[str, Any]) -> None:
    h = people["admin"]["h"]
    unknown = db_client.post(
        "/api/v1/threat-models",
        json={
            "application_id": "5e7e1ed6-0000-4000-8000-00000000ffff",
            "name": "X",
            "method": "stride",
        },
        headers=h,
    )
    assert unknown.status_code == 422
    app = register(db_client, h)
    db_client.patch(
        f"/api/v1/applications/{app['id']}",
        json={"version": app["version"], "status": "retired"},
        headers=h,
    )
    retired = db_client.post(
        "/api/v1/threat-models",
        json={"application_id": app["id"], "name": "X", "method": "stride"},
        headers=h,
    )
    assert retired.status_code == 409


def test_the_app_role_cannot_delete_the_catalogue(
    db_app: FastAPI, db_client: TestClient, people: dict[str, Any]
) -> None:
    db_client.get("/api/v1/governance/controls", headers=people["viewer"]["h"])
    for table in ("controls", "requirements"):
        with db_app.state.session_factory() as db, pytest.raises(ProgrammingError):
            db.execute(text(f"DELETE FROM sentinel.{table}"))  # noqa: S608 - constant names


def test_a_lead_deletes_an_application_model_and_the_audit_log_keeps_it(
    db_app: FastAPI, db_client: TestClient, people: dict[str, Any]
) -> None:
    lead = people["lead"]["h"]
    model = new_model(db_client, lead, register(db_client, people["admin"]["h"])["id"])
    url = f"/api/v1/threat-models/{model['id']}"
    db_client.post(f"{url}/elements", json={"kind": "boundary", "name": "Edge"}, headers=lead)
    db_client.post(
        f"{url}/threats",
        json={
            "title": "Token replay",
            "stride": "S",
            "likelihood": 3,
            "impact": 3,
            "controls": ["C-ID-03"],
            "boundaries": ["TB1"],
        },
        headers=lead,
    )
    assert db_client.delete(url, headers=people["viewer"]["h"]).status_code == 403
    gone = db_client.delete(url, headers=lead)
    assert gone.status_code == 204, gone.text
    assert db_client.get(url, headers=lead).status_code == 404
    listed = db_client.get("/api/v1/threat-models", headers=lead).json()["items"]
    assert [m for m in listed if m["origin"] == "app"] == []
    (deleted,) = audit_entries(db_app, "threat_model.deleted")
    assert deleted.resource_id == model["id"]
    assert deleted.details["threats"] == [
        {"ref": "TH-001", "title": "Token replay", "risk": 9, "status": "open"}
    ]
    assert deleted.details["elements"] == {"boundary": 1}

    own = catalogue_model(db_client, lead)
    refused = db_client.delete(f"/api/v1/threat-models/{own['id']}", headers=people["admin"]["h"])
    assert refused.status_code == 409
    assert refused.json()["error"]["code"] == "maintained_as_code"


def test_analysts_and_viewers_cannot_archive(db_client: TestClient, people: dict[str, Any]) -> None:
    admin = people["admin"]["h"]
    model = new_model(db_client, admin, register(db_client, admin)["id"])
    for who in ("analyst", "viewer"):
        r = db_client.post(
            f"/api/v1/threat-models/{model['id']}/archive",
            json={"version": model["version"]},
            headers=people[who]["h"],
        )
        assert r.status_code == 403
        detail = db_client.get(f"/api/v1/threat-models/{model['id']}", headers=people[who]["h"])
        assert detail.json()["permissions"]["can_archive"] is False
    own = catalogue_model(db_client, admin)
    refused = db_client.post(
        f"/api/v1/threat-models/{own['id']}/archive",
        json={"version": own["version"]},
        headers=admin,
    )
    assert refused.json()["error"]["code"] == "maintained_as_code"
