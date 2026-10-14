"""The deploy pipeline's CI gate (ADR-0030): only a commit whose every CI check is green deploys."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "ci-status.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("ci_status", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ci = _load()


def run(name: str, status: str = "completed", conclusion: str | None = "success") -> dict[str, Any]:
    return {"name": name, "status": status, "conclusion": conclusion}


def test_a_commit_deploys_only_when_every_check_is_green() -> None:
    ok, lines = ci.evaluate([run("ci/backend"), run("ci/docs", conclusion="skipped")])
    assert ok
    assert all(line.strip().startswith("ok") for line in lines)


@pytest.mark.parametrize(
    "runs",
    [
        [],  # no results at all: never assumed green
        [run("ci/backend"), run("ci/scan", conclusion="failure")],
        [run("ci/backend"), run("ci/scan", status="in_progress", conclusion=None)],
        [run("ci/backend", conclusion="cancelled")],
        [run("ci/backend", conclusion="neutral")],
    ],
)
def test_missing_pending_or_failed_checks_refuse(runs: list[dict[str, Any]]) -> None:
    ok, _ = ci.evaluate(runs)
    assert not ok


def test_an_unreachable_github_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    def unreachable(slug: str, sha: str) -> list[dict[str, Any]]:
        raise OSError("no network")

    monkeypatch.setattr(ci, "fetch", unreachable)
    assert ci.main(["Bionic-Hacker/Sentinel-Edge", "0" * 40]) == 1
