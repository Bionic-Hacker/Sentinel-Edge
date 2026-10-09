"""Security posture score API models (spec §40; ADR-0022)."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel


class FactorKind(StrEnum):
    COVERAGE = "coverage"  # share of the category's catalogue controls that are implemented
    SIGNAL = "signal"  # a live deduction: past-SLA findings, open incidents, carried risk


class CategoryState(StrEnum):
    MEASURED = "measured"  # at least one control implemented
    PLANNED = "planned"  # every control is still planned: scored 0, labelled planned


class Factor(BaseModel):
    kind: FactorKind
    label: str
    points: int  # coverage: the points it contributes; signals: negative deductions
    refs: list[str]  # control references, or the records behind a signal
    link: str | None  # where in the application to see them


class Category(BaseModel):
    key: str
    label: str
    score: int
    state: CategoryState
    implemented: int
    planned: int
    factors: list[Factor]


class TrendPoint(BaseModel):
    taken_at: datetime
    overall: int
    built_scope: int


class Posture(BaseModel):
    overall: int  # mean over every category, planned ones at 0
    built_scope: int  # mean over measured categories only
    categories: list[Category]
    method: str
    trend: list[TrendPoint]
    computed_at: datetime
