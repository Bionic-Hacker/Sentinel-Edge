"""Guards on the REAL vs SIMULATED register (spec §43). These tests are the enforcement."""

import re
from pathlib import Path

import pytest

from app.core.capabilities import CAPABILITIES
from app.core.provenance import Provenance, Status

# Phases are built out of numerical order to defer AWS cost (ADR-0016): 1, 2, 6, 7, 8, 10, 9,
# then 3, 4, 5, 11, 12. The rule is completion, not phase number.
COMPLETED_PHASES = frozenset({1, 2, 6, 7})


def test_keys_are_unique() -> None:
    keys = [c.key for c in CAPABILITIES]
    assert len(keys) == len(set(keys))


def test_no_implemented_real_aws_capability_before_aws_phases() -> None:
    # Phase 1 has no Terraform-managed AWS resources, so nothing may claim to be a live
    # AWS control. Update this guard deliberately when Phase 3+ ships real integrations.
    offenders = [
        c.key
        for c in CAPABILITIES
        if c.provenance is Provenance.REAL_AWS and c.status is Status.IMPLEMENTED
    ]
    assert offenders == []


def test_implemented_items_belong_to_completed_phases() -> None:
    assert all(c.phase in COMPLETED_PHASES for c in CAPABILITIES if c.status is Status.IMPLEMENTED)


def test_planned_items_belong_to_phases_not_yet_completed() -> None:
    assert all(c.phase not in COMPLETED_PHASES for c in CAPABILITIES if c.status is Status.PLANNED)


def test_simulations_are_never_marked_real() -> None:
    sims = [c for c in CAPABILITIES if c.key.startswith(("sim.", "demo."))]
    assert sims
    assert all(c.provenance in {Provenance.SIMULATED, Provenance.DEMO} for c in sims)


def test_all_real_aws_entries_are_namespaced() -> None:
    assert all(
        c.key.startswith("aws.") for c in CAPABILITIES if c.provenance is Provenance.REAL_AWS
    )


MODULES_TS = Path(__file__).resolve().parents[3] / "frontend" / "src" / "app" / "modules.ts"


@pytest.mark.skipif(not MODULES_TS.exists(), reason="frontend sources not present")
def test_every_module_capability_key_is_registered() -> None:
    # Each UI module lists the capabilities it shows; a key missing from the register would
    # silently show nothing, so the UI and the register must agree.
    source = MODULES_TS.read_text()
    blocks = re.findall(r"capabilityKeys:\s*\[(.*?)\]", source, re.S)
    keys = {k for block in blocks for k in re.findall(r'"([a-z0-9_.]+)"', block)}
    assert keys, "no capability keys found in modules.ts"
    assert keys <= {c.key for c in CAPABILITIES}, sorted(keys - {c.key for c in CAPABILITIES})
