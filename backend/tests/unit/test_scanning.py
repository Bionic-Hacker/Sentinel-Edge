"""The scan gate (Phase 8): every scanner's report reduces to one finding format, and the policy
blocks exactly what ADR-0020 says it blocks. Fixtures in scan_reports/ are real reports from
Semgrep, Bandit, Checkov and Gitleaks (trimmed), and Trivy and ZAP reports in their documented
formats with synthetic CVE IDs."""

from __future__ import annotations

import io
import json
import shutil
from datetime import date
from pathlib import Path

import pytest

from app.scanning import gate
from app.scanning.findings import Finding, fingerprint
from app.scanning.gate import Acceptance, AcceptanceError, evaluate, load_acceptances
from app.scanning.parsers import (
    load_reports,
    parse_bandit,
    parse_checkov,
    parse_gitleaks,
    parse_semgrep,
    parse_trivy,
    parse_zap,
    relative_path,
)

REPORTS = Path(__file__).parent / "scan_reports"
TODAY = date(2026, 10, 8)


def load(name: str) -> object:
    return json.loads((REPORTS / name).read_text())


def by_rule(findings: list[Finding]) -> dict[str, Finding]:
    return {f.rule_id: f for f in findings}


# --- Parsers ------------------------------------------------------------------------------------


def test_semgrep_uses_the_rules_declared_severity_and_short_ids() -> None:
    findings = by_rule(parse_semgrep(load("semgrep.json")))  # type: ignore[arg-type]
    assert set(findings) == {
        "sentineledge-sql-built-from-strings",
        "sentineledge-secret-in-log",
        "sentineledge-shell-command",
    }
    sql = findings["sentineledge-sql-built-from-strings"]
    assert (sql.severity, sql.category, sql.tool) == ("critical", "sast", "semgrep")
    assert sql.component == "backend/app/example.py"
    assert sql.location.startswith("backend/app/example.py:")
    assert findings["sentineledge-secret-in-log"].severity == "medium"
    assert findings["sentineledge-shell-command"].severity == "high"


def test_semgrep_fingerprint_survives_code_moving(tmp_path: Path) -> None:
    doc: dict = load("semgrep.json")  # type: ignore[assignment]
    result = doc["results"][0]
    line = result["start"]["line"]
    source = tmp_path / "backend" / "app" / "example.py"
    source.parent.mkdir(parents=True)
    code = "    sqlalchemy.text(f\"SELECT * FROM users WHERE name = '{name}'\")"
    source.write_text("\n" * (line - 1) + code + "\n")
    before = parse_semgrep({"results": [result]}, tmp_path)[0].fingerprint

    # Five unrelated lines added above: the finding moves but is the same issue.
    source.write_text("\n" * (line + 4) + code + "\n")
    moved = dict(result, start=dict(result["start"], line=line + 5))
    after = parse_semgrep({"results": [moved]}, tmp_path)[0]
    assert after.fingerprint == before
    assert after.location.endswith(f":{line + 5}")


def test_bandit_findings_are_normalised() -> None:
    findings = by_rule(parse_bandit(load("bandit.json")))  # type: ignore[arg-type]
    assert findings["B602"].severity == "high"
    assert findings["B403"].severity == "low"
    assert findings["B602"].component == "backend/app/example.py"


def test_trivy_dependency_scan() -> None:
    findings = by_rule(parse_trivy(load("trivy-fs.json")))  # type: ignore[arg-type]
    high = findings["CVE-2099-0001"]
    assert (high.category, high.severity, high.component) == ("sca", "high", "examplelib@1.2.0")
    assert high.cve == "CVE-2099-0001"
    assert high.cvss == 8.1  # the highest score across sources
    assert high.fixed_version == "1.2.1"
    assert high.fixable
    assert high.location == "backend/requirements.txt"
    medium = findings["CVE-2099-0002"]
    assert medium.fixed_version is None
    assert not medium.fixable


def test_trivy_image_scan_is_a_container_finding() -> None:
    findings = by_rule(parse_trivy(load("trivy-image-api.json")))  # type: ignore[arg-type]
    unfixed = findings["CVE-2099-1000"]
    assert (unfixed.category, unfixed.severity) == ("container", "critical")
    assert not unfixed.fixable
    assert unfixed.location.startswith("sentineledge-api:latest")
    assert findings["CVE-2099-1001"].fixable


def test_checkov_failures_without_severity_count_as_high() -> None:
    findings = by_rule(parse_checkov(load("checkov.json")))  # type: ignore[arg-type]
    assert set(findings) == {"CKV_DOCKER_7", "CKV_DOCKER_5"}
    assert all(f.severity == "high" and f.category == "iac" for f in findings.values())
    assert findings["CKV_DOCKER_7"].component == "backend/Dockerfile"


def test_checkov_reports_from_several_frameworks() -> None:
    doc = load("checkov.json")
    secrets = {
        "check_type": "secrets",
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_SECRET_6",
                    "check_name": "Base64 High Entropy String",
                    "file_path": "/x.py",
                    "file_line_range": [3, 3],
                    "resource": "abc",
                }
            ]
        },
    }
    findings = parse_checkov([doc, secrets, {"passed": 0, "failed": 0}])
    secret = by_rule(findings)["CKV_SECRET_6"]
    assert (secret.category, secret.severity) == ("secret", "critical")
    assert len(findings) == 3


def test_gitleaks_secrets_are_critical() -> None:
    [leak] = parse_gitleaks(load("gitleaks.json"))  # type: ignore[arg-type]
    assert (leak.category, leak.severity, leak.rule_id) == ("secret", "critical", "github-pat")
    assert "REDACTED" not in leak.title
    assert "Revoke" in (leak.recommendation or "")


def test_zap_alerts_map_risk_to_severity() -> None:
    findings = by_rule(parse_zap(load("zap-baseline.json")))  # type: ignore[arg-type]
    csp = findings["10038"]
    assert (csp.category, csp.severity) == ("dast", "medium")
    assert csp.title.endswith("(2 URLs)")
    assert csp.location == "http://web:8080/robots.txt"
    assert (
        csp.recommendation == "Ensure that your web server sets the Content-Security-Policy header."
    )
    assert csp.references == ("CWE-693",)
    assert findings["10049"].severity == "info"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("/src/backend/app/x.py", "backend/app/x.py"),
        ("/repo/frontend/Dockerfile", "frontend/Dockerfile"),
        ("./scripts/scan.sh", "scripts/scan.sh"),
        ("backend/app/x.py", "backend/app/x.py"),
    ],
)
def test_paths_are_made_repository_relative(raw: str, expected: str) -> None:
    assert relative_path(raw) == expected


def test_load_reports_reads_every_scanner_and_ignores_other_files(tmp_path: Path) -> None:
    for report in REPORTS.iterdir():
        shutil.copy(report, tmp_path / report.name)
    (tmp_path / "sbom-api.cdx.json").write_text("{}")
    (tmp_path / "scan.log").write_text("noise")
    findings, read = load_reports(tmp_path)
    assert "sbom-api.cdx.json" not in read
    assert len(read) == 7
    assert {f.tool for f in findings} == {
        "semgrep",
        "bandit",
        "trivy",
        "checkov",
        "gitleaks",
        "zap",
    }
    assert len({f.fingerprint for f in findings}) == len(findings)


def test_a_corrupt_report_is_an_error_not_a_pass(tmp_path: Path) -> None:
    (tmp_path / "semgrep.json").write_text("{not json")
    with pytest.raises(ValueError, match="Expecting property name"):
        load_reports(tmp_path)


# --- Policy -------------------------------------------------------------------------------------


def all_findings() -> list[Finding]:
    findings, _ = load_reports(REPORTS)
    return findings


def test_policy_blocks_fixable_critical_and_high_only() -> None:
    decision = evaluate(all_findings(), [], TODAY)
    blocking = {f.rule_id for f in decision.blocking}
    assert {
        "sentineledge-sql-built-from-strings",
        "B602",
        "CVE-2099-0001",
        "CVE-2099-1001",
        "CKV_DOCKER_7",
        "github-pat",
    } <= blocking
    assert all(f.severity in {"critical", "high"} for f in decision.blocking)
    # A critical package vulnerability with no published fix is reported, not blocking.
    assert [f.rule_id for f in decision.awaiting_fix] == ["CVE-2099-1000"]
    assert {"sentineledge-secret-in-log", "B403", "CVE-2099-0002", "10038"} <= {
        f.rule_id for f in decision.other
    }
    assert not decision.passed


def accept(**overrides: object) -> Acceptance:
    values: dict = {
        "id": "ACC-9001",
        "justification": "Synthetic test acceptance.",
        "compensating_control": "Read-only filesystem.",
        "approver": "Bionic-Hacker",
        "expires": date(2026, 12, 31),
        "rule": "CVE-2099-1001",
    }
    values.update(overrides)
    return Acceptance(**values)


def test_an_accepted_risk_covers_its_finding_until_it_expires() -> None:
    findings = [f for f in all_findings() if f.rule_id == "CVE-2099-1001"]
    covered = evaluate(findings, [accept()], TODAY)
    assert covered.passed
    assert covered.accepted[0][1].id == "ACC-9001"

    lapsed = evaluate(findings, [accept(expires=date(2026, 10, 7))], TODAY)
    assert not lapsed.passed
    assert [a.id for a in lapsed.expired] == ["ACC-9001"]


def test_acceptances_match_narrowly() -> None:
    findings = [f for f in all_findings() if f.rule_id == "CVE-2099-1001"]
    other_component = evaluate(findings, [accept(component="openssl@*")], TODAY)
    assert not other_component.passed
    assert [a.id for a in other_component.unused] == ["ACC-9001"]
    by_fingerprint = evaluate(
        findings, [accept(rule=None, fingerprint=findings[0].fingerprint)], TODAY
    )
    assert by_fingerprint.passed


def write_toml(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "accepted.toml"
    path.write_text(body)
    return path


VALID = """
[[accepted]]
id = "ACC-0001"
match = { tool = "trivy", rule = "CVE-2099-1001", component = "libpatched1@*" }
justification = "Not reachable."
compensating_control = "No shell in the runtime path."
approver = "Bionic-Hacker"
expires = 2026-12-31
"""


def test_acceptances_load_from_toml(tmp_path: Path) -> None:
    [a] = load_acceptances(write_toml(tmp_path, VALID))
    assert (a.id, a.tool, a.rule, a.component, a.expires) == (
        "ACC-0001",
        "trivy",
        "CVE-2099-1001",
        "libpatched1@*",
        date(2026, 12, 31),
    )
    assert load_acceptances(None) == []
    assert load_acceptances(tmp_path / "missing.toml") == []


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (('approver = "Bionic-Hacker"\n', ""), "missing approver"),
        (("expires = 2026-12-31", 'expires = "soon"'), "TOML date"),
        (
            (
                'match = { tool = "trivy", rule = "CVE-2099-1001", component = "libpatched1@*" }',
                'match = { tool = "trivy" }',
            ),
            "fingerprint or a rule",
        ),
    ],
)
def test_malformed_acceptances_are_refused(
    tmp_path: Path, change: tuple[str, str], message: str
) -> None:
    with pytest.raises(AcceptanceError, match=message):
        load_acceptances(write_toml(tmp_path, VALID.replace(*change)))


def test_duplicate_acceptance_ids_are_refused(tmp_path: Path) -> None:
    with pytest.raises(AcceptanceError, match="duplicate"):
        load_acceptances(write_toml(tmp_path, VALID + VALID))


def test_the_repositorys_own_register_is_valid() -> None:
    register = Path(__file__).resolve().parents[3] / "scanning" / "accepted-findings.toml"
    if not register.exists():
        pytest.skip("repository root not present")
    for a in load_acceptances(register):
        assert a.id.startswith("ACC-")


# --- Command line -------------------------------------------------------------------------------


def run(argv: list[str]) -> tuple[int, str]:
    out = io.StringIO()
    code = gate.main(argv, out)
    return code, out.getvalue()


def test_gate_fails_on_blocking_findings_and_writes_the_findings(tmp_path: Path) -> None:
    target = tmp_path / "findings.json"
    code, text = run([str(REPORTS), "--json", str(target), "--today", "2026-10-08"])
    assert code == 1
    assert "BLOCKING" in text
    assert "Awaiting an upstream fix (1)" in text
    assert text.rstrip().endswith("blocking")
    payload = json.loads(target.read_text())
    assert payload["passed"] is False
    assert len(payload["findings"]) == len(all_findings())


def test_gate_passes_when_only_unblocked_findings_remain(tmp_path: Path) -> None:
    (tmp_path / "zap-baseline.json").write_text((REPORTS / "zap-baseline.json").read_text())
    (tmp_path / "trivy-image-api.json").write_text(
        json.dumps(
            {
                "ArtifactType": "container_image",
                "ArtifactName": "api",
                "Results": [
                    {
                        "Target": "api",
                        "Vulnerabilities": [
                            json.loads((REPORTS / "trivy-image-api.json").read_text())["Results"][
                                0
                            ]["Vulnerabilities"][0]
                        ],
                    }
                ],
            }
        )
    )
    code, text = run([str(tmp_path)])
    assert code == 0
    assert "PASS: 0 blocking" in text


@pytest.mark.parametrize("setup", ["missing", "empty"])
def test_gate_refuses_to_pass_without_reports(tmp_path: Path, setup: str) -> None:
    target = tmp_path / "reports"
    if setup == "empty":
        target.mkdir()
    code, text = run([str(target)])
    assert code == 2
    assert "make scan" in text or "refusing" in text


def test_gate_refuses_a_malformed_register(tmp_path: Path) -> None:
    bad = write_toml(tmp_path, '[[accepted]]\nid = "ACC-1"\n')
    code, text = run([str(REPORTS), "--accepted", str(bad)])
    assert code == 2
    assert "cannot evaluate" in text


def test_fingerprints_ignore_nothing_but_order() -> None:
    assert fingerprint("a", "b") == fingerprint("a", "b") != fingerprint("b", "a")
