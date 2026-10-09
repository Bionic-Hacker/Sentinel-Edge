"""Build the governance catalogue from the reviewed Markdown documents (Phase 10, ADR-0022).

SentinelEdge's own threat model (`docs/threat-model.md`) and control catalogue
(`docs/security-controls.md`) are maintained as code: they change only through reviewed pull
requests. `scripts/governance-catalogue.py` runs this parser and writes
`app/governance/catalogue.json`, which ships with the API and is loaded into the database
(app.services.governance.sync_catalogue). `tests/unit/test_governance_catalogue.py` re-runs the
parser on the documents and fails if the JSON differs, so the documents, the shipped catalogue
and the application can never disagree.

Pure functions over text: no I/O beyond what the caller passes in.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

LXI = "L\u00d7I"  # the threat tables' likelihood x impact column
THREAT_ID = re.compile(r"^T-[A-Z]+-\d{2}$")
CONTROL_ID = re.compile(r"^C-[A-Z]+-\d{2}$")
CONTROL_REF = re.compile(r"C-[A-Z]+-\d{2}")
RANGE = re.compile(r"(C-[A-Z]+-)(\d{2})\.\.(\d{2})")
PHASE_REF = re.compile(r"\bP(\d{1,2})\b")
SECTION = re.compile(r"^## (.+)$")
SUBSECTION = re.compile(r"^### (.+)$")
BOUNDARY = re.compile(r"\b(TB\d)\b\s*[—-]\s*([^,]+)")


class CatalogueError(ValueError):
    """The documents do not have the structure the catalogue needs."""


def _cells(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def _plain(text: str) -> str:
    """Markdown cell text as plain text: no emphasis or code markers, collapsed whitespace.
    (Evidence is parsed from the raw cell first, where the backticks mark what to verify.)"""
    return re.sub(r"\s+", " ", text.replace("**", "").replace("`", "")).strip()


def _tables(lines: list[str]) -> list[tuple[int, list[str], list[list[str]]]]:
    """Every table as (line index of its header, header cells, body rows)."""
    out: list[tuple[int, list[str], list[list[str]]]] = []
    i = 0
    while i < len(lines):
        if (
            lines[i].startswith("|")
            and i + 1 < len(lines)
            and re.match(r"^\|[-|]+\|$", lines[i + 1])
        ):
            header = _cells(lines[i])
            rows: list[list[str]] = []
            j = i + 2
            while j < len(lines) and lines[j].startswith("|"):
                rows.append(_cells(lines[j]))
                j += 1
            out.append((i, header, rows))
            i = j
        else:
            i += 1
    return out


def _headings(lines: list[str]) -> list[tuple[int, int, str]]:
    """(line index, level, text) for every ## and ### heading."""
    out = []
    for i, line in enumerate(lines):
        if m := SECTION.match(line):
            out.append((i, 2, m.group(1).strip()))
        elif m := SUBSECTION.match(line):
            out.append((i, 3, m.group(1).strip()))
    return out


def _heading_before(headings: list[tuple[int, int, str]], index: int, level: int) -> str:
    title = ""
    for i, lvl, text in headings:
        if i > index:
            break
        if lvl == level:
            title = text
    return title


def _section_lines(lines: list[str], title_prefix: str) -> list[str]:
    start = next((i for i, x in enumerate(lines) if x.startswith(f"## {title_prefix}")), None)
    if start is None:
        raise CatalogueError(f"missing section: {title_prefix}")
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")), len(lines))
    return lines[start + 1 : end]


def _items(block: list[str], marker: re.Pattern[str]) -> list[str]:
    """List items (numbered or bulleted) joined across their continuation lines."""
    items: list[str] = []
    for line in block:
        if m := marker.match(line):
            items.append(m.group(1).strip())
        elif items and line.startswith("  ") and line.strip():
            items[-1] += " " + line.strip()
    return [_plain(x) for x in items]


def threat_status(text: str) -> str:
    """Normalise a threat's free-text status to one of the model's statuses."""
    s = _plain(text).lower()
    for prefix, status in (
        ("closed", "closed"),
        ("accepted", "accepted"),
        ("not exposed", "not_exposed"),
        ("planned", "planned"),
    ):
        if s.startswith(prefix):
            return status
    if re.match(r"^mitigated( \(|$| and )", s):
        return "mitigated"
    if "mitigated" in s:
        return "partly_mitigated"
    return "open"


def _evidence(text: str) -> list[dict[str, str]]:
    """Structured evidence from a cell: tests and test files must exist (verified by a test)."""
    found: list[dict[str, str]] = []
    for token in re.findall(r"`([^`]+)`", text):
        if re.fullmatch(r"test_[a-z0-9_]+", token):
            kind = "test"
        elif re.fullmatch(r"(tests/[\w/]+/)?test_[a-z0-9_]+\.py", token):
            kind = "test_file"
        elif re.fullmatch(r"[\w-]+\.test\.tsx?", token):
            kind = "frontend_test"
        elif token.startswith("make "):
            kind = "command"
        else:
            continue
        item = {"kind": kind, "ref": token.rsplit("/", 1)[-1] if kind == "test_file" else token}
        if item not in found:
            found.append(item)
    return found


def _expand(cell: str) -> list[str]:
    refs: list[str] = []
    for part in re.split(r",\s*", cell):
        if m := RANGE.search(part):
            refs += [f"{m.group(1)}{n:02d}" for n in range(int(m.group(2)), int(m.group(3)) + 1)]
        else:
            refs += CONTROL_REF.findall(part)
    return refs


def parse_controls(text: str) -> list[dict[str, Any]]:
    lines = text.splitlines()
    headings = _headings(lines)
    layers: dict[str, str] = {}
    controls: dict[str, dict[str, Any]] = {}
    for index, header, rows in _tables(lines):
        section = _heading_before(headings, index, 2)
        if header[:3] == ["#", "Layer", "Why it exists"]:
            for row in rows:
                for ref in _expand(row[3]):
                    layers.setdefault(ref, row[1])
        elif header == ["ID", "Control", "Implementation", "Evidence"]:
            m = re.search(r"Phase (\d+)", section)
            if not m:
                raise CatalogueError(f"implemented controls outside a phase section: {section}")
            phase = int(m.group(1))
            for row in rows:
                ref, title, implementation, evidence = row
                if not CONTROL_ID.match(ref):
                    raise CatalogueError(f"bad control ID: {ref}")
                entry: dict[str, Any] = {
                    "phase": phase,
                    "title": _plain(title),
                    "implementation": _plain(implementation),
                    "evidence_text": _plain(evidence),
                    "evidence": _evidence(evidence),
                }
                if ref in controls:
                    controls[ref]["extensions"].append(entry)
                else:
                    controls[ref] = {"ref": ref, "status": "implemented", **entry, "extensions": []}
        elif header == ["ID", "Control", "Phase"]:
            for ref, title, planned_phase in rows:
                if not CONTROL_ID.match(ref):
                    raise CatalogueError(f"bad control ID: {ref}")
                if ref in controls:
                    raise CatalogueError(f"{ref} is both implemented and planned")
                controls[ref] = {
                    "ref": ref,
                    "status": "planned",
                    "phase": int(planned_phase),
                    "title": _plain(title),
                    "implementation": "",
                    "evidence_text": "",
                    "evidence": [],
                    "extensions": [],
                }
    out = []
    for ref in sorted(controls):
        c = controls[ref]
        c["family"] = ref.split("-")[1]
        c["layer"] = layers.get(ref)
        out.append(c)
    if not out:
        raise CatalogueError("no controls found")
    return out


def parse_threat_model(text: str) -> dict[str, Any]:
    lines = text.splitlines()
    head = "\n".join(lines[:12])
    version = re.search(r"\*\*Version:\*\* ([\d.]+)", head)
    if not version:
        raise CatalogueError("threat model version not found")
    headings = _headings(lines)
    elements: list[dict[str, Any]] = []
    threats: list[dict[str, Any]] = []
    boundaries: dict[str, str] = {}
    for _, level, title in headings:
        if level == 3:
            for ref, name in BOUNDARY.findall(title):
                boundaries.setdefault(ref, _plain(name))
    for ref in sorted(boundaries, key=lambda r: int(r[2:])):
        elements.append(
            {
                "kind": "boundary",
                "ref": ref,
                "name": boundaries[ref],
                "description": "",
                "attributes": {},
            }
        )

    current_boundaries: list[str] = []
    for index, header, rows in _tables(lines):
        section = _heading_before(headings, index, 2)
        if header[:2] == ["ID", "Asset"]:
            for ref, name, why in rows:
                elements.append(
                    {
                        "kind": "asset",
                        "ref": ref,
                        "name": _plain(name),
                        "description": _plain(why),
                        "attributes": {},
                    }
                )
        elif header[:2] == ["Flow", "From → To"]:
            for ref, route, data, crossing in rows:
                elements.append(
                    {
                        "kind": "flow",
                        "ref": ref,
                        "name": _plain(route),
                        "description": _plain(data),
                        "attributes": {"boundaries": re.findall(r"TB\d", crossing)},
                    }
                )
        elif header and header[0] == "ID" and "Threat" in header and "Control IDs" in header:
            sub = _heading_before(headings, index, 3)
            refs = re.findall(r"\bTB\d\b", sub)
            if refs:
                current_boundaries = refs
            col = {name: i for i, name in enumerate(header)}
            stride_col = next(k for k in header if k.startswith("STRIDE"))
            for row in rows:
                ref = row[0]
                if not THREAT_ID.match(ref):
                    raise CatalogueError(f"bad threat ID: {ref}")
                li = re.fullmatch(r"(\d)\u00d7(\d)", row[col[LXI]])
                if not li:
                    raise CatalogueError(f"{ref}: bad likelihood x impact")
                status_text = _plain(row[col["Status"]])
                threats.append(
                    {
                        "ref": ref,
                        "group": sub,
                        "boundaries": list(current_boundaries),
                        "stride": row[col[stride_col]],
                        "owasp": row[col["OWASP"]] if "OWASP" in col else "",
                        "title": _plain(row[col["Threat"]]),
                        "likelihood": int(li.group(1)),
                        "impact": int(li.group(2)),
                        "mitigation": _plain(row[col["Control(s)"]]),
                        "controls": CONTROL_REF.findall(row[col["Control IDs"]]),
                        "status": threat_status(status_text),
                        "status_text": status_text,
                        "phases": sorted({int(p) for p in PHASE_REF.findall(status_text)}),
                    }
                )
        elif section.startswith("3.") and header and header[0] == "ID":
            raise CatalogueError(f"threat table without a Control IDs column near line {index + 1}")

    for n, item in enumerate(
        _items(_section_lines(lines, "4. Attack paths"), re.compile(r"^\d+\. (.+)$")), 1
    ):
        title, _, rest = item.partition(". ")
        elements.append(
            {
                "kind": "attack_path",
                "ref": f"AP-{n}",
                "name": title.strip(),
                "description": rest.strip(),
                "attributes": {"threats": sorted(set(re.findall(r"T-[A-Z]+-\d{2}", rest)))},
            }
        )
    residual = next(t for _, lvl, t in headings if lvl == 2 and t.startswith("5. Residual risk"))
    for n, item in enumerate(
        _items(_section_lines(lines, "5. Residual risk"), re.compile(r"^- (.+)$")), 1
    ):
        elements.append(
            {
                "kind": "residual_risk",
                "ref": f"RR-{n}",
                "name": item.split(". ")[0][:200],
                "description": item,
                "attributes": {"heading": residual},
            }
        )
    seen: set[tuple[str, str]] = set()
    for e in elements:
        key = (e["kind"], e["ref"])
        if key in seen:
            raise CatalogueError(f"duplicate {e['kind']} {e['ref']}")
        seen.add(key)
    if len({t["ref"] for t in threats}) != len(threats):
        raise CatalogueError("duplicate threat IDs")
    return {
        "version": version.group(1),
        "method": "stride",
        "elements": elements,
        "threats": threats,
    }


def parse_requirements(text: str) -> list[dict[str, Any]]:
    lines = text.splitlines()
    for _, header, rows in _tables(lines):
        if header[:3] == ["Requirement", "Threat", "Control"]:
            return [
                {
                    "ref": f"REQ-{n:02d}",
                    "title": _plain(r[0]),
                    "threats": re.findall(r"T-[A-Z]+-\d{2}", r[1]),
                    "control_text": _plain(r[2]),
                    "implementation": _plain(r[3]),
                    "evidence_text": _plain(r[4]),
                    "evidence": _evidence(r[4]),
                    "phase_text": _plain(r[5]),
                }
                for n, r in enumerate(rows, 1)
            ]
    raise CatalogueError("requirement matrix not found")


def build_catalogue(threat_model_md: str, controls_md: str) -> dict[str, Any]:
    """The whole catalogue, checked for dangling references, with a content digest."""
    controls = parse_controls(controls_md)
    model = parse_threat_model(threat_model_md)
    requirements = parse_requirements(controls_md)
    known_controls = {c["ref"] for c in controls}
    known_threats = {t["ref"] for t in model["threats"]}
    for t in model["threats"]:
        if missing := sorted(set(t["controls"]) - known_controls):
            raise CatalogueError(f"{t['ref']} names unknown controls: {', '.join(missing)}")
    for r in requirements:
        if missing := sorted(set(r["threats"]) - known_threats):
            raise CatalogueError(f"{r['ref']} names unknown threats: {', '.join(missing)}")
    body = {"format": 1, "model": model, "controls": controls, "requirements": requirements}
    canonical = json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return {**body, "digest": hashlib.sha256(canonical.encode()).hexdigest()}


def render(catalogue: dict[str, Any]) -> str:
    return json.dumps(catalogue, indent=1, ensure_ascii=False, sort_keys=True) + "\n"
