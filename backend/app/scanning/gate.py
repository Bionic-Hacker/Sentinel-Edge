"""The scan gate: decide whether a build may proceed, from normalised findings.

Policy (ADR-0020):
* A critical or high finding blocks the build, unless an accepted-risk record covers it.
* A critical or high vulnerability in a third-party package with **no fixed version published**
  cannot be fixed by changing this repository. It does not block; it is reported on every run
  as "awaiting an upstream fix", so it is never silently ignored, and it blocks as soon as a
  fix is released.
* An accepted-risk record must name who accepted it, why, the compensating control and an
  expiry date. Once it expires it no longer covers anything, so the finding blocks again.
* Medium, low and info findings never block; they are recorded and reported.

Accepted risks live in scanning/accepted-findings.toml, reviewed like code.

    python -m app.scanning.gate ../reports/scan --root .. \\
        --accepted ../scanning/accepted-findings.toml
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import sys
import tomllib
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, TextIO

from app.scanning.findings import BLOCKING_SEVERITIES, SEVERITIES, Finding, severity_rank
from app.scanning.parsers import load_reports

REQUIRED = ("id", "justification", "compensating_control", "approver", "expires")


class AcceptanceError(ValueError):
    """The accepted-findings file is malformed: the gate refuses to guess."""


@dataclass(frozen=True)
class Acceptance:
    id: str
    justification: str
    compensating_control: str
    approver: str
    expires: date
    fingerprint: str | None = None
    tool: str | None = None
    rule: str | None = None
    component: str | None = None  # fnmatch pattern

    def matches(self, f: Finding) -> bool:
        if self.fingerprint:
            return f.fingerprint == self.fingerprint
        return (
            (self.tool is None or self.tool == f.tool)
            and (self.rule is None or self.rule == f.rule_id)
            and (self.component is None or fnmatch.fnmatch(f.component, self.component))
        )

    def expired(self, today: date) -> bool:
        return today > self.expires


def load_acceptances(path: Path | None) -> list[Acceptance]:
    if path is None or not path.exists():
        return []
    data = tomllib.loads(path.read_text())
    out: list[Acceptance] = []
    seen: set[str] = set()
    for entry in data.get("accepted", []):
        missing = [k for k in REQUIRED if not entry.get(k)]
        if missing:
            raise AcceptanceError(f"{entry.get('id', '?')}: missing {', '.join(missing)}")
        match = entry.get("match") or {}
        if not (match.get("fingerprint") or match.get("rule")):
            raise AcceptanceError(f"{entry['id']}: match needs a fingerprint or a rule")
        if entry["id"] in seen:
            raise AcceptanceError(f"{entry['id']}: duplicate ID")
        seen.add(entry["id"])
        expires = entry["expires"]
        if not isinstance(expires, date):
            raise AcceptanceError(f"{entry['id']}: expires must be a TOML date (YYYY-MM-DD)")
        out.append(
            Acceptance(
                id=entry["id"],
                justification=entry["justification"],
                compensating_control=entry["compensating_control"],
                approver=entry["approver"],
                expires=expires,
                fingerprint=match.get("fingerprint"),
                tool=match.get("tool"),
                rule=match.get("rule"),
                component=match.get("component"),
            )
        )
    return out


@dataclass
class Decision:
    blocking: list[Finding] = field(default_factory=list)
    awaiting_fix: list[Finding] = field(default_factory=list)  # critical/high, no fix exists
    accepted: list[tuple[Finding, Acceptance]] = field(default_factory=list)
    other: list[Finding] = field(default_factory=list)  # medium, low, info
    expired: list[Acceptance] = field(default_factory=list)
    unused: list[Acceptance] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.blocking


def evaluate(findings: list[Finding], acceptances: list[Acceptance], today: date) -> Decision:
    decision = Decision()
    active = [a for a in acceptances if not a.expired(today)]
    decision.expired = [a for a in acceptances if a.expired(today)]
    used: set[str] = set()
    for f in sorted(
        findings, key=lambda x: (severity_rank(x.severity), x.tool, x.rule_id, x.location)
    ):
        if f.severity not in BLOCKING_SEVERITIES:
            decision.other.append(f)
            continue
        cover = next((a for a in active if a.matches(f)), None)
        if cover is not None:
            decision.accepted.append((f, cover))
            used.add(cover.id)
        elif not f.fixable:
            decision.awaiting_fix.append(f)
        else:
            decision.blocking.append(f)
    decision.unused = [a for a in active if a.id not in used]
    return decision


def _line(f: Finding) -> str:
    fix = f" -> {f.fixed_version}" if f.fixed_version else ""
    return f"  {f.severity.upper():8} {f.tool:8} {f.rule_id:28} {f.component}{fix}  [{f.location}]"


def report(decision: Decision, findings: list[Finding], read: list[str], out: TextIO) -> None:
    counts = Counter(f.severity for f in findings)
    summary = ", ".join(f"{counts.get(s, 0)} {s}" for s in SEVERITIES)
    print(f"Scan gate: {len(findings)} findings from {len(read)} reports ({summary})", file=out)
    print(f"  reports: {', '.join(read) or 'none'}", file=out)
    if decision.blocking:
        print(f"\nBLOCKING ({len(decision.blocking)}): fix, or record an accepted risk", file=out)
        for f in decision.blocking:
            print(_line(f), file=out)
    if decision.awaiting_fix:
        print(
            f"\nAwaiting an upstream fix ({len(decision.awaiting_fix)}): "
            "blocks once a fix is released",
            file=out,
        )
        for f in decision.awaiting_fix:
            print(_line(f), file=out)
    if decision.accepted:
        print(f"\nAccepted risks ({len(decision.accepted)})", file=out)
        for f, a in decision.accepted:
            print(f"{_line(f)}  {a.id}, expires {a.expires.isoformat()}", file=out)
    for a in decision.expired:
        print(
            f"\nEXPIRED acceptance {a.id} (expired {a.expires.isoformat()}): "
            "no longer covers anything",
            file=out,
        )
    for a in decision.unused:
        print(f"\nUnused acceptance {a.id}: matches no current finding; remove it", file=out)
    print(f"\n{'PASS' if decision.passed else 'FAIL'}: {len(decision.blocking)} blocking", file=out)


def main(argv: list[str] | None = None, out: TextIO = sys.stdout) -> int:
    parser = argparse.ArgumentParser(prog="scan-gate", description="Apply the scan gate policy.")
    parser.add_argument("reports", type=Path, help="directory written by scripts/scan.sh")
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="repository root")
    parser.add_argument("--accepted", type=Path, help="accepted-findings TOML file")
    parser.add_argument("--json", type=Path, help="write all normalised findings here")
    parser.add_argument("--today", type=date.fromisoformat, help="evaluate expiry as of this date")
    parser.add_argument(
        "--expect",
        action="append",
        default=[],
        metavar="REPORT",
        help="a report file that must be present (repeatable); a missing one fails the gate",
    )
    args = parser.parse_args(argv)

    if not args.reports.is_dir():
        print(f"scan-gate: no reports directory at {args.reports}; run `make scan` first", file=out)
        return 2
    try:
        findings, read = load_reports(args.reports, args.root)
        acceptances = load_acceptances(args.accepted)
    except (ValueError, KeyError, AcceptanceError) as exc:  # includes json.JSONDecodeError
        print(f"scan-gate: cannot evaluate: {exc}", file=out)
        return 2
    if not read:
        print("scan-gate: no scanner reports found; refusing to pass an empty scan", file=out)
        return 2
    missing = sorted(set(args.expect) - set(read))
    if missing:
        # A scanner that failed or never ran must not let the build pass on the others' reports.
        print(f"scan-gate: missing reports: {', '.join(missing)}; run `make scan`", file=out)
        return 2
    today = args.today or datetime.now(UTC).date()
    decision = evaluate(findings, acceptances, today)
    if args.json:
        payload: dict[str, Any] = {
            "generated_at": datetime.now(UTC).isoformat(),
            "reports": read,
            "passed": decision.passed,
            "findings": [f.to_dict() for f in findings],
        }
        args.json.write_text(json.dumps(payload, indent=2) + "\n")
    report(decision, findings, read, out)
    return 0 if decision.passed else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
