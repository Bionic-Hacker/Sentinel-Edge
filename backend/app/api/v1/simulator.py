"""Attack simulator API (spec §23). Everything here is SIMULATED and targets SentinelEdge only:
requests name a scenario, never a target."""

from __future__ import annotations

from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Path, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.authz import Principal, require_roles
from app.core.clock import utcnow
from app.core.request_context import request_context
from app.db.session import get_db
from app.models.simulation import SimulationRun
from app.models.user import Role
from app.schemas.simulator import (
    RunList,
    RunOut,
    RunRequest,
    ScenarioList,
    ScenarioOut,
    WafModeRequest,
    WafRuleList,
    WafRuleOut,
)
from app.services import simulator

router = APIRouter(prefix="/simulator", tags=["simulator"])
# Investigators can see what was simulated; only leads run simulations or change the simulated WAF.
viewers = require_roles(Role.ADMIN, Role.SECURITY_ENGINEER, Role.ANALYST)
operators = require_roles(Role.ADMIN, Role.SECURITY_ENGINEER)


def _run_out(run: SimulationRun) -> RunOut:
    return RunOut(
        id=run.id,
        reference=run.reference,
        scenario=simulator.Scenario(run.scenario),
        started_by_label=run.started_by_label,
        started_at=run.started_at,
        completed_at=run.completed_at,
        seed=run.seed,
        summary=run.summary,
    )


@router.get("/scenarios", response_model=ScenarioList)
def list_scenarios(_: Principal = Depends(viewers)) -> ScenarioList:  # noqa: B008
    return ScenarioList(
        items=[
            ScenarioOut(
                scenario=s.scenario,
                name=s.name,
                description=s.description,
                demonstrates=s.demonstrates,
            )
            for s in simulator.CATALOGUE
        ]
    )


@router.get("/runs", response_model=RunList)
def list_runs(
    _: Principal = Depends(viewers),  # noqa: B008
    db: Session = Depends(get_db),  # noqa: B008
) -> RunList:
    runs = db.scalars(select(SimulationRun).order_by(SimulationRun.number.desc()).limit(25)).all()
    return RunList(items=[_run_out(r) for r in runs])


@router.post("/runs", response_model=RunOut, status_code=status.HTTP_201_CREATED)
def run_scenario(
    body: RunRequest,
    request: Request,
    principal: Principal = Depends(operators),  # noqa: B008
    db: Session = Depends(get_db),  # noqa: B008
) -> RunOut:
    return _run_out(simulator.run_scenario(db, principal, body.scenario, request_context(request)))


@router.get("/waf-rules", response_model=WafRuleList)
def list_waf_rules(
    _: Principal = Depends(viewers),  # noqa: B008
    db: Session = Depends(get_db),  # noqa: B008
) -> WafRuleList:
    since = utcnow() - timedelta(hours=24)
    return WafRuleList(
        web_acl=simulator.WEB_ACL,
        note=(
            "SIMULATED WAF: changing a rule here affects simulations only. Real AWS WAF rules "
            "change through Terraform (ADR-0008, Phase 5)."
        ),
        items=[
            WafRuleOut(
                rule_id=rule.rule_id,
                description=rule.description,
                category=rule.category,
                severity=rule.severity,
                comparable_group=simulator.comparable_group(rule.rule_id),
                mode=mode,
                matches_24h=matches,
                updated_at=state.updated_at if state else None,
                updated_by_label=state.updated_by_label if state else None,
            )
            for rule, mode, matches, state in simulator.iter_rules(db, since)
        ],
    )


@router.put("/waf-rules/{rule_id}", response_model=WafModeRequest)
def set_waf_rule_mode(
    rule_id: Annotated[str, Path(max_length=32, pattern=r"^[A-Z]+-[0-9]{3}$")],
    body: WafModeRequest,
    request: Request,
    principal: Principal = Depends(operators),  # noqa: B008
    db: Session = Depends(get_db),  # noqa: B008
) -> WafModeRequest:
    mode = simulator.set_waf_mode(db, principal, rule_id, body.mode, request_context(request))
    return WafModeRequest(mode=mode)
