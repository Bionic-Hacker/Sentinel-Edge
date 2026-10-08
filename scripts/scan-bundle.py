"""Bundle a scan's results for import: the gate's findings.json and the Syft SBOMs.

    python scripts/scan-bundle.py reports/scan > bundle.json

Writes {"findings": <findings.json>, "sboms": {"api": <CycloneDX>, "web": ..., "source": ...}}
to stdout, for `python -m app.cli import-scan` (make scan-import). Standard library only: it runs
on the host, before anything reaches the API container.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

_SBOM = re.compile(r"^sbom-([a-z0-9][a-z0-9-]{0,31})\.cdx\.json$")


def bundle(directory: Path) -> dict[str, object]:
    findings_path = directory / "findings.json"
    if not findings_path.is_file():
        raise SystemExit(f"{findings_path} not found: run `make scan` (the gate writes it) first")
    sboms = {}
    for path in sorted(directory.iterdir()):
        match = _SBOM.match(path.name)
        if match:
            sboms[match.group(1)] = json.loads(path.read_text())
    return {"findings": json.loads(findings_path.read_text()), "sboms": sboms}


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: scan-bundle.py <reports directory>", file=sys.stderr)
        return 2
    json.dump(bundle(Path(argv[0])), sys.stdout, separators=(",", ":"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
