#!/usr/bin/env python3
"""Regenerate backend/app/governance/catalogue.json from the threat model and control catalogue.

Run after editing docs/threat-model.md or docs/security-controls.md (`make governance-catalogue`)
and commit both. CI fails if they disagree (tests/unit/test_governance_catalogue.py).
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from app.governance.catalogue_source import CatalogueError, build_catalogue, render  # noqa: E402

OUT = ROOT / "backend" / "app" / "governance" / "catalogue.json"


def main() -> int:
    try:
        catalogue = build_catalogue(
            (ROOT / "docs" / "threat-model.md").read_text(encoding="utf-8"),
            (ROOT / "docs" / "security-controls.md").read_text(encoding="utf-8"),
        )
    except CatalogueError as exc:
        print(f"governance-catalogue: {exc}", file=sys.stderr)
        return 1
    OUT.write_text(render(catalogue), encoding="utf-8")
    model = catalogue["model"]
    print(
        f"Wrote {OUT.relative_to(ROOT)}: threat model v{model['version']}, "
        f"{len(model['threats'])} threats, {len(catalogue['controls'])} controls, "
        f"{len(catalogue['requirements'])} requirements; digest {catalogue['digest'][:12]}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
