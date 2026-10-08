"""Vulnerability management (Phase 8, ADR-0021): importing scans, de-duplication, fixed and
reopened findings, SLAs, risk acceptance, findings as security events, and who sees what."""

from __future__ import annotations

import io
import json
import uuid
from datetime import UTC, date, datetime, timedelta
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.exc import ProgrammingError

from app import cli
from app.models.incident import Incident
from app.models.security_event import EventSource, SecurityEvent
from app.models.user import Role
from app.models.vulnerability import (
    AcceptanceEnd,
    RiskAcceptance,
    ScanRun,
    ScanSource,
    Vulnerability,
    VulnStatus,
)
from app.schemas.vulnerabilities import ScanReport
from app.services.vulnerabilities import ScanImportError, expire_acceptances, import_scan
from tests.conftest import make_settings
from tests.helpers import audit_entries, bearer, create_user, session_token

pytestmark = [pytest.mark.security, pytest.mark.db]

ALL_REPORTS = [
    "bandit.json",
    "checkov.json",
    "gitleaks.json",
    "semgrep.json",
    "trivy-fs.json",
    "trivy-image-api.json",
    "trivy-image-web.json",
]
SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "metadata": {"component": {"name": "sentineledge-api:scan", "version": "sha256:abc"}},
    "components": [
        {
            "name": "fastapi",
            "version": "0.142.0",
            "type": "library",
            "purl": "pkg:pypi/fastapi@0.142.0",
            "licenses": [{"license": {"id": "MIT"}}],
        },
        {
            "name": "zlib1g",
            "version": "1:1.3",
            "type": "library",
            "purl": "pkg:deb/debian/zlib1g@1.3",
            "licenses": [{"expression": "Zlib"}],
        },
        {"name": "<script>alert(1)</script>\x07", "type": "library"},
    ],
}


def finding(key: str, severity: str = "high", **overrides: Any) -> dict[str, Any]:
    base = {
        "tool": "semgrep",
        "category": "sast",
        "rule_id": f"sentineledge-rule-{key}",
        "title": f"Weakness {key}",
        "severity": severity,
        "component": f"backend/app/{key}.py",
        "location": f"backend/app/{key}.py:10",
        "fingerprint": (key.encode().hex() * 32)[:32],
        "references": [],
    }
    return {**base, **overrides}


def package(
    key: str, severity: str = "high", fixed: str | None = "2.0", **kw: Any
) -> dict[str, Any]:
    return finding(
        key,
        severity,
        tool="trivy",
        category="container",
        rule_id=f"CVE-2099-{key}",
        cve=f"CVE-2099-{key}",
        component=f"lib{key}@1.0",
        location="sentineledge-api:scan (debian 13.7)",
        fixed_version=fixed,
        **kw,
    )


def report(
    *findings: dict[str, Any], reports: list[str] | None = None, passed: bool = True
) -> ScanReport:
    return ScanReport.model_validate(
        {
            "generated_at": datetime.now(UTC).isoformat(),
            "reports": reports or ALL_REPORTS,
            "passed": passed,
            "findings": list(findings),
        }
    )


def run_import(
    db_app: FastAPI,
    scan: ScanReport,
    sboms: dict[str, Any] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    with db_app.state.session_factory() as db:
        run = import_scan(
            db,
            application_slug="sentineledge",
            report=scan,
            sboms=sboms or {},
            source=ScanSource.LOCAL,
            commit_sha="a" * 40,
            branch="main",
            actor_label="cli:tester@example.com",
            now=now,
        )
        db.commit()
        return dict(run.summary)


def vulns(db_app: FastAPI) -> dict[str, Vulnerability]:
    with db_app.state.session_factory() as db:
        return {v.rule_id: v for v in db.scalars(select(Vulnerability))}


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


# --- Import -------------------------------------------------------------------------------------


def test_import_deduplicates_and_records_the_scan(db_app: FastAPI) -> None:
    first = run_import(
        db_app, report(finding("a"), finding("a"), finding("b", "low")), {"api": SBOM}
    )
    assert first | {"by_severity": None} == {
        "total": 2,
        "by_severity": None,
        "new": 2,
        "reopened": 0,
        "fixed": 0,
        "unchanged": 0,
        "acceptances_expired": 0,
        "sboms": ["api"],
        "events": 1,  # only the high finding
    }
    assert first["by_severity"]["high"] == 1
    second = run_import(db_app, report(finding("a"), finding("b", "low")))
    assert (second["new"], second["unchanged"]) == (0, 2)
    found = vulns(db_app)
    assert set(found) == {"sentineledge-rule-a", "sentineledge-rule-b"}
    a = found["sentineledge-rule-a"]
    assert a.status is VulnStatus.OPEN
    assert a.first_scan_id != a.last_scan_id
    assert a.sla_due_at is not None
    assert a.sla_due_at - a.first_seen_at == timedelta(days=30)
    assert found["sentineledge-rule-b"].sla_due_at - found["sentineledge-rule-b"].first_seen_at == (
        timedelta(days=180)
    )
    (entry, _) = audit_entries(db_app, "scan.imported")
    assert entry.details["application"] == "sentineledge"
    assert entry.details["new"] == 2


def test_a_finding_no_longer_reported_is_fixed_and_comes_back_reopened(db_app: FastAPI) -> None:
    run_import(db_app, report(finding("a"), package("1")))
    summary = run_import(db_app, report(package("1")))
    assert summary["fixed"] == 1
    fixed = vulns(db_app)["sentineledge-rule-a"]
    assert fixed.status is VulnStatus.FIXED
    assert fixed.resolved_at is not None

    later = datetime.now(UTC) + timedelta(days=3)
    summary = run_import(db_app, report(finding("a"), package("1")), now=later)
    assert summary["reopened"] == 1
    back = vulns(db_app)["sentineledge-rule-a"]
    assert (back.status, back.resolved_at, back.times_reopened) == (VulnStatus.OPEN, None, 1)
    assert back.sla_due_at == later + timedelta(days=30)  # the SLA clock restarts


def test_a_scan_without_a_report_never_fixes_that_reports_findings(db_app: FastAPI) -> None:
    zap = finding("z", "medium", tool="zap", category="dast", location="http://localhost:8080/")
    dast = [*ALL_REPORTS, "zap-baseline.json", "zap-api.json"]
    run_import(db_app, report(zap, reports=dast))
    summary = run_import(db_app, report())  # no DAST this time
    assert summary["fixed"] == 0
    summary = run_import(db_app, report(reports=[*ALL_REPORTS, "zap-baseline.json"]))
    assert summary["fixed"] == 0  # the baseline alone cannot vouch for the API scan's findings
    assert vulns(db_app)["sentineledge-rule-z"].status is VulnStatus.OPEN
    summary = run_import(db_app, report(reports=dast))
    assert summary["fixed"] == 1


def test_severity_change_keeps_the_original_sla_clock(db_app: FastAPI) -> None:
    run_import(db_app, report(finding("a", "medium")))
    before = vulns(db_app)["sentineledge-rule-a"]
    run_import(db_app, report(finding("a", "critical")))
    after = vulns(db_app)["sentineledge-rule-a"]
    assert after.severity == "critical"
    assert after.sla_due_at == before.first_seen_at + timedelta(days=7)


def test_new_critical_findings_are_security_events_and_fixable_ones_open_an_incident(
    db_app: FastAPI,
) -> None:
    run_import(
        db_app,
        report(
            finding("s", "critical", tool="gitleaks", category="secret"),
            package("2", "critical", fixed=None),  # nothing to do yet: an event, no incident
            finding("m", "medium"),  # below the event threshold
        ),
    )
    with db_app.state.session_factory() as db:
        events = db.scalars(
            select(SecurityEvent).where(SecurityEvent.source == EventSource.APPSEC)
        ).all()
        assert sorted(str(e.category) for e in events) == [
            "exposed_secret",
            "vulnerable_dependency",
        ]
        assert all(e.evidence["application"] == "sentineledge" for e in events)
        unfixable = next(e for e in events if e.category == "vulnerable_dependency")
        assert unfixable.evidence["fixable"] is False
        assert unfixable.incident_id is None
        incidents = db.scalars(select(Incident)).all()
        assert [str(i.category) for i in incidents] == ["exposed_secret"]


def test_events_per_import_are_bounded(db_app: FastAPI) -> None:
    many = [finding(f"k{i:03d}", "high") for i in range(60)]
    summary = run_import(db_app, report(*many))
    assert summary["events"] == 50
    with db_app.state.session_factory() as db:
        events = db.scalars(
            select(SecurityEvent).where(SecurityEvent.source == EventSource.APPSEC)
        ).all()
    assert len(events) == 51  # 50 findings plus one summary
    assert any("10 more" in e.title for e in events)


def test_import_is_all_or_nothing(db_app: FastAPI) -> None:
    with pytest.raises(ScanImportError, match="not a CycloneDX"):
        run_import(db_app, report(finding("a")), {"api": {"bomFormat": "SPDX"}})
    with db_app.state.session_factory() as db:
        assert db.scalars(select(Vulnerability)).all() == []
        assert db.scalars(select(ScanRun)).all() == []


def test_scanner_text_is_bounded_and_control_characters_replaced() -> None:
    parsed = report(finding("a", title="x" * 5000 + "\x1b[31m", references=["r"] * 50))
    f = parsed.findings[0]
    assert len(f.title) == 300
    assert len(f.references) == 10
    long = report(finding("a", title="\x1b[31mred"))
    assert long.findings[0].title == "?[31mred"


# --- Risk acceptance and expiry -----------------------------------------------------------------


def _accept(client: TestClient, h: dict[str, str], vid: uuid.UUID, version: int, **kw: Any) -> Any:
    body = {
        "justification": "Only reachable from the internal network today.",
        "compensating_control": "Edge allow-list and WAF rule SQLI-001 in block mode.",
        "expires_on": (date.today() + timedelta(days=20)).isoformat(),
        "version": version,
        **kw,
    }
    return client.post(f"/api/v1/vulnerabilities/{vid}/acceptances", json=body, headers=h)


def test_risk_acceptance_lifecycle(
    db_app: FastAPI, db_client: TestClient, people: dict[str, Any]
) -> None:
    run_import(db_app, report(finding("a", "critical")))
    v = vulns(db_app)["sentineledge-rule-a"]
    lead = people["lead"]["h"]

    too_long = _accept(
        db_client, lead, v.id, v.version, expires_on=(date.today() + timedelta(days=45)).isoformat()
    )
    assert too_long.status_code == 422
    assert "at most 30 days" in too_long.json()["error"]["message"]

    accepted = _accept(db_client, lead, v.id, v.version)
    assert accepted.status_code == 201, accepted.text
    body = accepted.json()
    assert body["status"] == "accepted_risk"
    assert body["can_revoke_acceptance"] is True
    (acceptance,) = body["acceptances"]
    assert acceptance["approver_label"] == "lead@example.com"
    assert acceptance["in_force"] is True

    again = _accept(db_client, lead, v.id, body["version"])
    assert again.status_code == 409  # only an open finding can be accepted

    revoked = db_client.post(
        f"/api/v1/vulnerabilities/{v.id}/acceptances/{acceptance['id']}/revoke",
        json={"note": "Control removed", "version": body["version"]},
        headers=lead,
    )
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["status"] == "open"
    assert revoked.json()["acceptances"][0]["end_reason"] == "revoked"
    actions = [e.action for e in audit_entries(db_app) if e.action.startswith("vulnerability.")]
    assert actions == ["vulnerability.risk_accepted", "vulnerability.acceptance_revoked"]


def test_an_expired_acceptance_reopens_its_finding(
    db_app: FastAPI, db_client: TestClient, people: dict[str, Any]
) -> None:
    run_import(db_app, report(finding("a")))
    v = vulns(db_app)["sentineledge-rule-a"]
    assert _accept(db_client, people["lead"]["h"], v.id, v.version).status_code == 201
    with db_app.state.session_factory() as db:
        assert expire_acceptances(db, datetime.now(UTC) + timedelta(days=21)) == 1
        db.commit()
        acceptance = db.scalar(select(RiskAcceptance))
        assert acceptance is not None
        assert acceptance.end_reason is AcceptanceEnd.EXPIRED
    assert vulns(db_app)["sentineledge-rule-a"].status is VulnStatus.OPEN
    assert audit_entries(db_app, "vulnerability.acceptance_expired")


def test_fixing_an_accepted_finding_ends_the_acceptance(
    db_app: FastAPI, db_client: TestClient, people: dict[str, Any]
) -> None:
    run_import(db_app, report(finding("a")))
    v = vulns(db_app)["sentineledge-rule-a"]
    assert _accept(db_client, people["lead"]["h"], v.id, v.version).status_code == 201
    run_import(db_app, report())
    assert vulns(db_app)["sentineledge-rule-a"].status is VulnStatus.FIXED
    with db_app.state.session_factory() as db:
        acceptance = db.scalar(select(RiskAcceptance))
        assert acceptance is not None
        assert acceptance.end_reason is AcceptanceEnd.FIXED


# --- Status workflow ----------------------------------------------------------------------------


def _status(
    client: TestClient, h: dict[str, str], vid: Any, status: str, version: int, **kw: Any
) -> Any:
    return client.post(
        f"/api/v1/vulnerabilities/{vid}/status",
        json={"status": status, "version": version, **kw},
        headers=h,
    )


def test_status_workflow_rules(
    db_app: FastAPI, db_client: TestClient, people: dict[str, Any]
) -> None:
    run_import(db_app, report(finding("a")))
    v = vulns(db_app)["sentineledge-rule-a"]
    admin = people["admin"]["h"]

    fixed = _status(db_client, admin, v.id, "fixed", v.version)
    assert fixed.status_code == 409  # fixed is set only by a scan
    moved = _status(db_client, admin, v.id, "in_progress", v.version)
    assert moved.status_code == 200, moved.text
    stale = _status(db_client, admin, v.id, "open", v.version)
    assert stale.status_code == 409
    assert stale.json()["error"]["code"] == "stale_version"

    version = moved.json()["version"]
    no_note = _status(db_client, admin, v.id, "false_positive", version)
    assert no_note.status_code == 422
    fp = _status(db_client, admin, v.id, "false_positive", version, note="Test fixture, not code")
    assert fp.status_code == 200
    assert fp.json()["allowed_statuses"] == ["open"]

    # A false positive stays one when the scanner reports it again.
    run_import(db_app, report(finding("a")))
    assert vulns(db_app)["sentineledge-rule-a"].status is VulnStatus.FALSE_POSITIVE


def test_developers_work_only_on_their_own_applications(
    db_app: FastAPI, db_client: TestClient, people: dict[str, Any]
) -> None:
    run_import(db_app, report(finding("a")))
    v = vulns(db_app)["sentineledge-rule-a"]
    dev = people["dev"]["h"]

    assert db_client.get("/api/v1/vulnerabilities", headers=dev).json()["items"] == []
    assert (
        db_client.get("/api/v1/vulnerabilities/overview", headers=dev).json()["active_total"] == 0
    )
    assert db_client.get("/api/v1/scans", headers=dev).json()["items"] == []
    denied = db_client.get(f"/api/v1/vulnerabilities/{v.id}", headers=dev)
    assert denied.status_code == 404
    assert audit_entries(db_app, "authz.denied")[-1].resource_type == "vulnerability"

    # Give the developer the application: now they see it and can move it, but not triage it.
    platform = db_client.get("/api/v1/applications", headers=people["admin"]["h"]).json()["items"][
        0
    ]
    owned = db_client.patch(
        f"/api/v1/applications/{platform['id']}",
        json={"owner_id": str(people["dev"]["user"].id), "version": platform["version"]},
        headers=people["admin"]["h"],
    )
    assert owned.status_code == 200, owned.text
    detail = db_client.get(f"/api/v1/vulnerabilities/{v.id}", headers=dev).json()
    assert detail["allowed_statuses"] == ["in_progress"]
    assert detail["can_accept_risk"] is False
    assert (
        _status(
            db_client, dev, v.id, "false_positive", v.version, note="I disagree here"
        ).status_code
        == 409
    )
    assert _status(db_client, dev, v.id, "in_progress", v.version).status_code == 200


def test_viewers_and_analysts_read_but_cannot_act(
    db_app: FastAPI, db_client: TestClient, people: dict[str, Any]
) -> None:
    run_import(db_app, report(finding("a")))
    v = vulns(db_app)["sentineledge-rule-a"]
    for who in ("viewer", "analyst"):
        h = people[who]["h"]
        detail = db_client.get(f"/api/v1/vulnerabilities/{v.id}", headers=h).json()
        assert (detail["allowed_statuses"], detail["can_accept_risk"]) == ([], False)
        assert _status(db_client, h, v.id, "in_progress", v.version).status_code == 403


# --- Reads --------------------------------------------------------------------------------------


def test_list_filters_and_overview(
    db_app: FastAPI, db_client: TestClient, people: dict[str, Any]
) -> None:
    run_import(
        db_app,
        report(finding("a", "critical"), package("1", "high", fixed=None), finding("c", "low")),
    )
    h = people["viewer"]["h"]

    def refs(**params: Any) -> list[str]:
        page = db_client.get("/api/v1/vulnerabilities", params=params, headers=h)
        assert page.status_code == 200, page.text
        return sorted(item["rule_id"] for item in page.json()["items"])

    assert refs(min_severity="high") == ["CVE-2099-1", "sentineledge-rule-a"]
    assert refs(fixable="false") == ["CVE-2099-1"]
    assert refs(category="container") == ["CVE-2099-1"]
    assert refs(q="rule-c") == ["sentineledge-rule-c"]
    assert refs(q="100%_") == []  # LIKE wildcards are literal
    assert len(refs(status=["open", "in_progress"])) == 3

    first = db_client.get("/api/v1/vulnerabilities", params={"limit": 2}, headers=h).json()
    assert len(first["items"]) == 2
    assert first["next_before"] is not None
    rest = db_client.get(
        "/api/v1/vulnerabilities", params={"limit": 2, "before": first["next_before"]}, headers=h
    ).json()
    assert len(rest["items"]) == 1
    assert rest["next_before"] is None

    (platform,) = db_client.get("/api/v1/applications", headers=h).json()["items"]
    assert platform["vulnerability_count"] == {
        "status": "measured",
        "value": 3,
        "note": "Open or in progress, from imported scans.",
    }
    assert platform["last_scan"]["note"].startswith("SCAN-0001, 0 days ago, commit aaaaaaa")

    overview = db_client.get("/api/v1/vulnerabilities/overview", headers=h).json()
    assert overview["active"] == {"critical": 1, "high": 1, "medium": 0, "low": 1, "info": 0}
    assert (overview["active_total"], overview["awaiting_fix"], overview["overdue"]) == (3, 1, 0)
    assert overview["last_scan"]["commit_sha"] == "a" * 40


def test_scans_and_sboms(db_app: FastAPI, db_client: TestClient, people: dict[str, Any]) -> None:
    run_import(db_app, report(finding("a")), {"api": SBOM})
    h = people["viewer"]["h"]
    (scan,) = db_client.get("/api/v1/scans", headers=h).json()["items"]
    assert scan["reference"] == "SCAN-0001"
    assert db_client.get(f"/api/v1/scans/{scan['id']}", headers=h).status_code == 200

    (sbom,) = db_client.get("/api/v1/sboms", headers=h).json()["items"]
    assert (sbom["artifact"], sbom["component_count"]) == ("api", 3)
    assert sbom["subject"] == "sentineledge-api:scan"
    detail = db_client.get(f"/api/v1/sboms/{sbom['id']}", params={"q": "zlib"}, headers=h).json()
    assert detail["components_total"] == 1
    assert detail["components"][0]["licenses"] == ["Zlib"]
    names = [
        c["name"]
        for c in db_client.get(f"/api/v1/sboms/{sbom['id']}", headers=h).json()["components"]
    ]
    assert "<script>alert(1)</script>?" in names  # stored as text, control character replaced

    doc = db_client.get(f"/api/v1/sboms/{sbom['id']}/document", headers=h)
    assert doc.status_code == 200
    assert doc.headers["content-type"] == "application/vnd.cyclonedx+json"
    assert doc.headers["content-disposition"].startswith("attachment;")
    assert json.loads(doc.content)["bomFormat"] == "CycloneDX"

    run_import(db_app, report(finding("a")), {"api": SBOM})
    assert len(db_client.get("/api/v1/sboms", headers=h).json()["items"]) == 1  # latest only
    every = db_client.get("/api/v1/sboms", params={"latest": "false"}, headers=h).json()
    assert len(every["items"]) == 2


# --- CLI and database guarantees ----------------------------------------------------------------


def test_cli_import(db_app: FastAPI) -> None:
    bundle = {
        "findings": json.loads(report(finding("a")).model_dump_json()),
        "sboms": {"source": SBOM},
    }
    out = io.StringIO()
    code = cli.main(
        ["import-scan", "--commit", "b" * 40, "--branch", "phase/8", "--actor", "me@example.com"],
        settings=make_settings(),
        out=out,
        stdin=io.StringIO(json.dumps(bundle)),
    )
    assert code == 0, out.getvalue()
    assert "Imported SCAN-0001 for sentineledge: 1 findings (1 new" in out.getvalue()

    for argv, payload in [
        (["import-scan", "--commit", "short"], bundle),
        (["import-scan"], {"findings": {"reports": []}}),
        (["import-scan"], {"findings": bundle["findings"], "sboms": {"../etc": SBOM}}),
        (["import-scan", "--application", "missing"], bundle),
    ]:
        assert (
            cli.main(
                argv,
                settings=make_settings(),
                out=io.StringIO(),
                stdin=io.StringIO(json.dumps(payload)),
            )
            != 0
        )


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE sentinel.scan_runs SET gate_passed = true",
        "DELETE FROM sentinel.scan_runs",
        "DELETE FROM sentinel.vulnerabilities",
        "DELETE FROM sentinel.risk_acceptances",
        "UPDATE sentinel.risk_acceptances SET justification = 'rewritten'",
        "UPDATE sentinel.risk_acceptances SET expires_at = now() + interval '10 years'",
        "UPDATE sentinel.sboms SET document_sha256 = 'x'",
        "DELETE FROM sentinel.sboms",
    ],
)
def test_the_app_role_cannot_rewrite_the_record(db_app: FastAPI, statement: str) -> None:
    with db_app.state.session_factory() as db, pytest.raises(ProgrammingError, match="permission"):
        db.execute(text(statement))


# --- Dashboard, API inventory and authenticated DAST (Part 3) ------------------------------------


def test_dashboard_vulnerability_control_is_measured_once_a_scan_exists(
    db_app: FastAPI, db_client: TestClient, people: dict[str, Any]
) -> None:
    h = people["lead"]["h"]

    def control() -> dict[str, Any]:
        body = db_client.get("/api/v1/security/overview", params={"view": "live"}, headers=h)
        assert body.status_code == 200, body.text
        result: dict[str, Any] = body.json()["controls"]["vulnerabilities"]
        return result

    assert control()["status"] == "not_connected"
    run_import(db_app, report(finding("a", "critical"), package("1", "high", fixed=None)))
    measured = control()
    assert measured["status"] == "measured"
    assert measured["values"]["open"] == 2
    assert measured["values"]["awaiting_fix"] == 1
    assert measured["values"]["fixable_critical_high"] == 1
    assert "SCAN-0001" in measured["summary"]
    # Scanner rule IDs are findings, not detection rules: they stay out of "most matched rules".
    overview = db_client.get("/api/v1/security/overview", params={"view": "live"}, headers=h).json()
    rules = [r["rule_id"] for r in overview["top_rules"]]
    assert not [r for r in rules if r.startswith(("CVE-", "sentineledge-rule"))]


def test_api_inventory_reports_the_last_authenticated_dast_scan(
    db_app: FastAPI, db_client: TestClient, people: dict[str, Any]
) -> None:
    h = people["lead"]["h"]

    def item() -> dict[str, Any]:
        items = db_client.get("/api/v1/api-security/inventory", headers=h).json()["items"]
        result: dict[str, Any] = items[0]
        return result

    assert item()["last_scan"] is None
    run_import(db_app, report(reports=[*ALL_REPORTS, "zap-baseline.json"]))
    baseline = item()
    assert baseline["last_scan"] is None
    assert "Only the passive baseline" in baseline["scan_note"]
    run_import(db_app, report(reports=[*ALL_REPORTS, "zap-baseline.json", "zap-api.json"]))
    authenticated = item()
    assert authenticated["last_scan"] is not None
    assert "SCAN-0002" in authenticated["scan_note"]


def test_dast_scanner_session_is_read_only_and_revocable(
    db_app: FastAPI, db_client: TestClient
) -> None:
    out = io.StringIO()
    assert cli.main(["dast-session", "issue"], settings=make_settings(), out=out) == 0
    h = bearer(out.getvalue().strip())
    assert db_client.get("/api/v1/vulnerabilities", headers=h).status_code == 200
    assert db_client.get("/api/v1/security-events", headers=h).status_code == 200  # VIEWER
    assert db_client.get("/api/v1/users", headers=h).status_code == 403
    write = db_client.post(
        f"/api/v1/vulnerabilities/{uuid.uuid4()}/status",
        json={"status": "in_progress", "version": 1},
        headers=h,
    )
    assert write.status_code == 403
    # A second issue reuses the account; revoke ends every scanner session at once.
    assert cli.main(["dast-session", "issue"], settings=make_settings(), out=io.StringIO()) == 0
    revoked = io.StringIO()
    assert cli.main(["dast-session", "revoke"], settings=make_settings(), out=revoked) == 0
    assert "Revoked 2" in revoked.getvalue()
    assert db_client.get("/api/v1/vulnerabilities", headers=h).status_code == 401
    actions = [e.action for e in audit_entries(db_app) if e.action.startswith("dast.")]
    assert actions == ["dast.session_issued", "dast.session_issued", "dast.session_revoked"]


def test_dast_scanner_account_must_stay_a_viewer(db_app: FastAPI) -> None:
    create_user(db_app, "dast-scanner@example.com", role=Role.ADMIN)
    assert cli.main(["dast-session", "issue"], settings=make_settings(), out=io.StringIO()) == 1


def test_openapi_document_lists_every_endpoint() -> None:
    out = io.StringIO()
    assert cli.main(["openapi"], settings=make_settings(), out=out) == 0
    paths = json.loads(out.getvalue())["paths"]
    assert "/api/v1/vulnerabilities/{vulnerability_id}" in paths
    assert "/api/v1/auth/logout" in paths

    dast = io.StringIO()
    argv = ["openapi", "--server", "http://localhost:8080"]
    assert cli.main(argv, settings=make_settings(), out=dast) == 0
    document = json.loads(dast.getvalue())
    assert document["servers"] == [{"url": "http://localhost:8080"}]
    assert "/api/v1/auth/logout" not in document["paths"]  # the scan must not end its session
    elsewhere = ["openapi", "--server", "https://victim.example"]
    assert cli.main(elsewhere, settings=make_settings(), out=io.StringIO()) == 2
