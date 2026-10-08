"""Threat modeling and the control catalogue (spec §36, §37; ADR-0022).

Two kinds of threat model live here:
* the **catalogue** model: SentinelEdge's own, maintained as code in `docs/threat-model.md` and
  loaded from `app/governance/catalogue.json` (app.services.governance.sync_catalogue). It is
  read-only in the application: it changes only through a reviewed pull request;
* **application** models: created in the application by leads for registered applications,
  with STRIDE or PASTA, and edited there (every change audited, optimistic concurrency).

Controls and requirements come from the catalogue only. Application threats may cite catalogue
controls. Nothing here is deleted by the application role (migration 0010): records are retired;
only the link tables allow DELETE, because changing a threat's controls replaces its links.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models._types import StrEnumType
from app.models.application import Application


class ControlStatus(StrEnum):
    IMPLEMENTED = "implemented"
    PLANNED = "planned"


class ModelMethod(StrEnum):
    STRIDE = "stride"
    PASTA = "pasta"


class ModelOrigin(StrEnum):
    CATALOGUE = "catalogue"  # maintained as code; read-only in the application
    APP = "app"  # created and edited in the application


class ModelStatus(StrEnum):
    DRAFT = "draft"
    ACTIVE = "active"
    ARCHIVED = "archived"


class ElementKind(StrEnum):
    ASSET = "asset"
    BOUNDARY = "boundary"  # trust boundary
    FLOW = "flow"  # data flow
    ATTACK_PATH = "attack_path"
    RESIDUAL_RISK = "residual_risk"


ELEMENT_PREFIX: dict[ElementKind, str] = {
    ElementKind.ASSET: "A",
    ElementKind.BOUNDARY: "TB",
    ElementKind.FLOW: "F",
    ElementKind.ATTACK_PATH: "AP-",
    ElementKind.RESIDUAL_RISK: "RR-",
}


class ThreatStatus(StrEnum):
    OPEN = "open"  # identified, nothing decided yet
    PLANNED = "planned"  # controls planned in a later phase
    PARTLY_MITIGATED = "partly_mitigated"
    MITIGATED = "mitigated"
    ACCEPTED = "accepted"  # accepted for a time (an exception records why)
    NOT_EXPOSED = "not_exposed"  # the attack surface does not exist (yet)
    CLOSED = "closed"  # no longer applies


# STRIDE letters ("T/R" for more than one) or an OWASP LLM Top 10 code.
STRIDE_PATTERN = r"^([STRIDE](/[STRIDE]){0,5}|LLM\d{2})$"

PASTA_STAGES = (
    "objectives",  # 1. business and security objectives
    "technical_scope",  # 2. technical scope
    "decomposition",  # 3. application decomposition
    "threat_analysis",  # 4. threat analysis
    "vulnerability_analysis",  # 5. weakness and vulnerability analysis
    "attack_modeling",  # 6. attack modelling
    "risk_impact",  # 7. risk and impact analysis
)


def _check(column: str, enum: type[StrEnum]) -> CheckConstraint:
    values = ", ".join(f"'{v.value}'" for v in enum)
    return CheckConstraint(f"{column} IN ({values})", name=f"{column}_valid")


class Control(Base):
    __tablename__ = "controls"
    __table_args__ = (
        _check("status", ControlStatus),
        CheckConstraint("ref ~ '^C-[A-Z]+-[0-9]{2}$'", name="ref_format"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    ref: Mapped[str] = mapped_column(String(16), unique=True, nullable=False)
    family: Mapped[str] = mapped_column(String(8), nullable=False)
    layer: Mapped[str | None] = mapped_column(String(60))
    title: Mapped[str] = mapped_column(String(400), nullable=False)
    status: Mapped[ControlStatus] = mapped_column(StrEnumType(ControlStatus, 12), nullable=False)
    phase: Mapped[int] = mapped_column(Integer, nullable=False)
    implementation: Mapped[str] = mapped_column(Text, nullable=False)
    # [{"kind": "test" | "test_file" | "frontend_test" | "command", "ref": "..."}]
    evidence: Mapped[list[dict[str, str]]] = mapped_column(JSONB, nullable=False)
    evidence_text: Mapped[str] = mapped_column(Text, nullable=False)
    # Later phases that extended the control (same shape as the control's own fields).
    extensions: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False)
    retired: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ThreatModel(Base):
    __tablename__ = "threat_models"
    __table_args__ = (
        _check("method", ModelMethod),
        _check("origin", ModelOrigin),
        _check("status", ModelStatus),
        CheckConstraint(
            "(origin = 'catalogue') = (catalogue_digest IS NOT NULL)", name="catalogue_has_digest"
        ),
        Index(
            "uq_threat_models_catalogue",
            "application_id",
            unique=True,
            postgresql_where=text("origin = 'catalogue'"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    number: Mapped[int] = mapped_column(Integer, Identity(always=True), unique=True, nullable=False)
    application_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey(Application.id), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    method: Mapped[ModelMethod] = mapped_column(StrEnumType(ModelMethod, 8), nullable=False)
    origin: Mapped[ModelOrigin] = mapped_column(StrEnumType(ModelOrigin, 12), nullable=False)
    status: Mapped[ModelStatus] = mapped_column(StrEnumType(ModelStatus, 12), nullable=False)
    scope: Mapped[str] = mapped_column(Text, nullable=False)
    version_label: Mapped[str] = mapped_column(String(32), nullable=False)
    # PASTA stage notes, keyed by PASTA_STAGES (empty for STRIDE models).
    pasta: Mapped[dict[str, str]] = mapped_column(JSONB, nullable=False)
    catalogue_digest: Mapped[str | None] = mapped_column(String(64))
    created_by_label: Mapped[str] = mapped_column(String(254), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)

    @property
    def reference(self) -> str:
        return f"TM-{self.number:04d}"


class ModelElement(Base):
    __tablename__ = "model_elements"
    __table_args__ = (
        _check("kind", ElementKind),
        UniqueConstraint("model_id", "kind", "ref", name="uq_model_elements_ref"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    model_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey(ThreatModel.id), nullable=False, index=True
    )
    kind: Mapped[ElementKind] = mapped_column(StrEnumType(ElementKind, 16), nullable=False)
    ref: Mapped[str] = mapped_column(String(16), nullable=False)
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    retired: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class Threat(Base):
    __tablename__ = "threats"
    __table_args__ = (
        _check("status", ThreatStatus),
        CheckConstraint("likelihood BETWEEN 1 AND 3", name="likelihood_range"),
        CheckConstraint("impact BETWEEN 1 AND 3", name="impact_range"),
        CheckConstraint(f"stride ~ '{STRIDE_PATTERN}'", name="stride_format"),
        UniqueConstraint("model_id", "ref", name="uq_threats_ref"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    model_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey(ThreatModel.id), nullable=False, index=True
    )
    ref: Mapped[str] = mapped_column(String(16), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    stride: Mapped[str] = mapped_column(String(16), nullable=False)
    owasp: Mapped[str] = mapped_column(String(64), nullable=False)
    group_name: Mapped[str] = mapped_column(String(200), nullable=False)
    boundaries: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    likelihood: Mapped[int] = mapped_column(Integer, nullable=False)
    impact: Mapped[int] = mapped_column(Integer, nullable=False)
    mitigation: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[ThreatStatus] = mapped_column(StrEnumType(ThreatStatus, 20), nullable=False)
    status_text: Mapped[str] = mapped_column(Text, nullable=False)
    phases: Mapped[list[int]] = mapped_column(JSONB, nullable=False)
    retired: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)

    @property
    def risk(self) -> int:
        return self.likelihood * self.impact


class ThreatControl(Base):
    __tablename__ = "threat_controls"

    threat_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey(Threat.id), primary_key=True)
    control_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey(Control.id), primary_key=True, index=True
    )


class Requirement(Base):
    """A row of the requirement → threat → control → implementation → evidence matrix."""

    __tablename__ = "requirements"
    __table_args__ = (CheckConstraint("ref ~ '^REQ-[0-9]{2,3}$'", name="ref_format"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    ref: Mapped[str] = mapped_column(String(8), unique=True, nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    control_text: Mapped[str] = mapped_column(Text, nullable=False)
    implementation: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[list[dict[str, str]]] = mapped_column(JSONB, nullable=False)
    evidence_text: Mapped[str] = mapped_column(Text, nullable=False)
    phase_text: Mapped[str] = mapped_column(String(100), nullable=False)
    position: Mapped[int] = mapped_column(Integer, nullable=False)
    retired: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class RequirementThreat(Base):
    __tablename__ = "requirement_threats"

    requirement_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey(Requirement.id), primary_key=True
    )
    threat_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey(Threat.id), primary_key=True, index=True
    )
