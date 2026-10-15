#!/usr/bin/env python3
"""Is every CI check for a commit green? The deploy pipeline's gate (ADR-0030).

    scripts/ci-status.py OWNER/REPO SHA

Reads GitHub's public check-runs API (no token: the repository is public). Exits 0 only if
GitHub has check runs for the commit and every one completed as success or skipped; a commit
with no results, or any pending or failed run, exits 1. Standard library only.
"""

from __future__ import annotations

import json
import sys
import urllib.request
from typing import Any

PASSING = ("success", "skipped")


def evaluate(runs: list[dict[str, Any]]) -> tuple[bool, list[str]]:
    """Whether the runs allow a deploy, and one line per run."""
    lines = []
    bad = 0
    for run in runs:
        ok = run.get("status") == "completed" and run.get("conclusion") in PASSING
        bad += not ok
        state = run.get("conclusion") or run.get("status")
        label = "ok  " if ok else ("FAIL" if run.get("status") == "completed" else "wait")
        lines.append(f"  {label} {run.get('name', '?')} ({state})")
    return bool(runs) and bad == 0, lines


def fetch(slug: str, sha: str) -> list[dict[str, Any]]:
    url = f"https://api.github.com/repos/{slug}/commits/{sha}/check-runs?per_page=100"
    request = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json"})
    # A fixed https:// URL built above; no caller-supplied scheme reaches urlopen.
    with urllib.request.urlopen(request, timeout=20) as response:  # noqa: S310
        runs: list[dict[str, Any]] = json.load(response)["check_runs"]
    return runs


def main(argv: list[str]) -> int:
    slug, sha = argv
    try:
        runs = fetch(slug, sha)
    except (OSError, ValueError, KeyError) as exc:
        print(f"deploy: cannot read CI results ({type(exc).__name__}); not deploying")
        return 1
    ok, lines = evaluate(runs)
    print("\n".join(lines))
    if not runs:
        print(f"deploy: GitHub has no CI results for {sha[:7]}; push it and let CI finish")
    elif not ok:
        print(f"deploy: not every CI check is green for {sha[:7]}; not deploying")
    else:
        print(f"  all {len(runs)} CI checks green for {sha[:7]}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
