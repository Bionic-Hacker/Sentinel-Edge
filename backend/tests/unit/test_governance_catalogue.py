"""The governance catalogue (Phase 10, ADR-0022): the shipped JSON must be exactly what the
reviewed documents produce, every threat must name its controls, every cited piece of evidence
must exist, and no control may claim a status its phase does not have."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from app.governance.catalogue_source import (
    CatalogueError,
    build_catalogue,
    parse_threat_model,
    render,
    threat_status,
)
from app.services.governance import CATALOGUE_PATH
from tests.unit.test_capabilities import COMPLETED_PHASES

TIMES = chr(0xD7)  # the multiplication sign the threat tables use in "L x I"
ROOT = Path(__file__).resolve().parents[3]
DOCS = ROOT / "docs"
needs_docs = pytest.mark.skipif(not DOCS.exists(), reason="documents not present")
CATALOGUE = json.loads(CATALOGUE_PATH.read_text(encoding="utf-8"))


def _docs() -> tuple[str, str]:
    return (
        (DOCS / "threat-model.md").read_text(encoding="utf-8"),
        (DOCS / "security-controls.md").read_text(encoding="utf-8"),
    )


@needs_docs
def test_the_shipped_catalogue_is_exactly_what_the_documents_produce() -> None:
    expected = render(build_catalogue(*_docs()))
    assert CATALOGUE_PATH.read_text(encoding="utf-8") == expected, (
        "docs/threat-model.md or docs/security-controls.md changed: run "
        "`make governance-catalogue` and commit the result"
    )


def test_every_threat_names_at_least_one_control() -> None:
    unmapped = [t["ref"] for t in CATALOGUE["model"]["threats"] if not t["controls"]]
    assert unmapped == []


def test_every_requirement_and_attack_path_names_known_threats() -> None:
    threats = {t["ref"] for t in CATALOGUE["model"]["threats"]}
    for r in CATALOGUE["requirements"]:
        assert r["threats"], r["ref"]
        assert set(r["threats"]) <= threats, r["ref"]
    for e in CATALOGUE["model"]["elements"]:
        if e["kind"] == "attack_path":
            assert set(e["attributes"]["threats"]) <= threats, e["ref"]


def test_control_status_matches_its_phase() -> None:
    """A planned control cannot belong to a finished phase, and an implemented one cannot
    belong to a phase that has not shipped: the catalogue cannot overstate what exists."""
    for c in CATALOGUE["controls"]:
        if c["status"] == "implemented":
            assert c["phase"] in COMPLETED_PHASES, c["ref"]
            for extension in c["extensions"]:
                assert extension["phase"] in COMPLETED_PHASES, c["ref"]
        else:
            assert c["phase"] not in COMPLETED_PHASES, c["ref"]


def _evidence() -> list[tuple[str, dict[str, str]]]:
    out = []
    for c in CATALOGUE["controls"]:
        for e in c["evidence"] + [e for x in c["extensions"] for e in x["evidence"]]:
            out.append((c["ref"], e))
    for r in CATALOGUE["requirements"]:
        out += [(r["ref"], e) for e in r["evidence"]]
    return out


@needs_docs
def test_every_cited_piece_of_evidence_exists() -> None:
    """Evidence a reviewer is told to run must exist: a renamed or deleted test fails here."""
    tests = ROOT / "backend" / "tests"
    test_source = "\n".join(p.read_text(encoding="utf-8") for p in tests.rglob("*.py"))
    test_files = {p.name for p in tests.rglob("test_*.py")}
    frontend = {p.name for p in (ROOT / "frontend" / "src").rglob("*.test.ts*")}
    targets = set(re.findall(r"^([a-z][a-z-]*):", (ROOT / "Makefile").read_text(), re.M))
    evidence = _evidence()
    assert len(evidence) > 80
    missing = []
    for ref, e in evidence:
        kind, name = e["kind"], e["ref"]
        if kind == "test":
            found = re.search(rf"def {re.escape(name)}\(", test_source) is not None
        elif kind == "test_file":
            found = name in test_files
        elif kind == "frontend_test":
            found = name in frontend
        else:
            found = name.removeprefix("make ").split()[0] in targets
        if not found:
            missing.append(f"{ref}: {kind} {name}")
    assert missing == []


@pytest.mark.parametrize(
    ("text", "status"),
    [
        ("**Mitigated (P2)**", "mitigated"),
        ("**Mitigated (P2, P6) and detected (P7)**: lockout", "mitigated"),
        ("**Mitigated locally (P6, tested)**: trusted proxy", "partly_mitigated"),
        ("Local analogue **mitigated (P1)**; AWS P3-4", "partly_mitigated"),
        ("HSTS mitigated (app); edge P5", "partly_mitigated"),
        ("Planned (P5)", "planned"),
        ("**Accepted (interim)** until P5/P6", "accepted"),
        ("**Not exposed; guard ready and tested (P6)**", "not_exposed"),
        ("**Closed (P2)**", "closed"),
        ("Under discussion", "open"),
    ],
)
def test_threat_statuses_are_normalised(text: str, status: str) -> None:
    assert threat_status(text) == status


MINIMAL_MODEL = """# Model
- **Version:** 1.0

## 3. Threats

### TB1 — Internet → Edge

| ID | STRIDE | Threat | L<x>I | Control(s) | Control IDs | Status |
|---|---|---|---|---|---|---|
| T-EDGE-01 | D | Flood | 2<x>2 | Rate rules | C-WAF-03 | Planned (P5) |

## 4. Attack paths (top three)

1. **Flood → outage.** Broken by T-EDGE-01 controls.

## 5. Residual risk (after Phase 1)

- Something remains.
""".replace("<x>", TIMES)
MINIMAL_CONTROLS = """# Controls

## 3. Matrix

| Requirement | Threat | Control | Implementation | Evidence | Phase |
|---|---|---|---|---|---|
| Availability | T-EDGE-01 | Rate rules | WAF | WAF logs | P5 |

## 4. Planned controls

| ID | Control | Phase |
|---|---|---|
| C-WAF-03 | Rate-based rules | 5 |
"""


def test_a_minimal_catalogue_builds_and_is_digested() -> None:
    catalogue = build_catalogue(MINIMAL_MODEL, MINIMAL_CONTROLS)
    assert [t["ref"] for t in catalogue["model"]["threats"]] == ["T-EDGE-01"]
    assert catalogue["model"]["threats"][0]["boundaries"] == ["TB1"]
    assert catalogue["requirements"][0]["threats"] == ["T-EDGE-01"]
    assert re.fullmatch(r"[0-9a-f]{64}", catalogue["digest"])
    assert build_catalogue(MINIMAL_MODEL, MINIMAL_CONTROLS)["digest"] == catalogue["digest"]


@pytest.mark.parametrize(
    ("model", "controls", "message"),
    [
        (
            MINIMAL_MODEL.replace("C-WAF-03 | Planned", "C-WAF-09 | Planned"),
            MINIMAL_CONTROLS,
            "unknown controls: C-WAF-09",
        ),
        (
            MINIMAL_MODEL,
            MINIMAL_CONTROLS.replace("| T-EDGE-01 | Rate", "| T-EDGE-07 | Rate"),
            "unknown threats: T-EDGE-07",
        ),
        (MINIMAL_MODEL.replace(f"2{TIMES}2", "two"), MINIMAL_CONTROLS, "bad likelihood"),
        (MINIMAL_MODEL.replace("**Version:** 1.0", "Version 1"), MINIMAL_CONTROLS, "version"),
    ],
)
def test_broken_documents_are_refused(model: str, controls: str, message: str) -> None:
    with pytest.raises(CatalogueError, match=message):
        build_catalogue(model, controls)


def test_a_threat_table_without_control_ids_is_refused() -> None:
    model = (
        MINIMAL_MODEL.replace(" Control IDs |", "")
        .replace("|---|---|---|---|---|---|---|", "|---|---|---|---|---|---|")
        .replace(" C-WAF-03 |", "")
    )
    with pytest.raises(CatalogueError, match="Control IDs"):
        parse_threat_model(model)
