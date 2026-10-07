"""Feature provenance: the mandatory REAL vs SIMULATED classification (spec §43, ADR-0009).

Every capability — and, from Phase 2, every telemetry row — carries one of these values. The UI
renders it as a badge so simulated or demo data can never be mistaken for a real AWS control.
"""

from __future__ import annotations

from enum import StrEnum


class Provenance(StrEnum):
    REAL_AWS = "REAL_AWS"  # backed by a live AWS API / resource managed by Terraform
    LOCAL = "LOCAL"  # real functionality running inside SentinelEdge itself
    SIMULATED = "SIMULATED"  # safe simulation of a security control or attack
    DEMO = "DEMO"  # synthetic seed data for demonstration


class Status(StrEnum):
    IMPLEMENTED = "implemented"
    PLANNED = "planned"
