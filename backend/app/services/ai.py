"""The AI security engine service (spec §21; ADR-0006, ADR-0007, ADR-0024).

Running an analysis (ADMIN, SECURITY_ENGINEER, ANALYST; DEVELOPERs on findings and threat models
of their own applications; never a VIEWER, so the read-only DAST scanner cannot spend tokens):

1. The subject is loaded under the same visibility rules as its own page (other IDs are "not
   found", audited), and reduced to an allow-list of fields (app.ai.guardrails).
2. Quotas are checked before anything is sent: requests per user per day, and tokens for all
   users per day. Over a limit, the call is refused (429) and the refusal audited.
3. The input is scored for prompt-injection signals and delimited under a per-call nonce.
4. The provider answers; the answer must meet the contract (app.ai.contract) or the analysis is
   stored as REJECTED with the reason. A provider failure is stored as FAILED.
5. The analysis, its proposals and an audit record (model, tokens, prompt-risk score, outcome)
   are written in one transaction. The provider call itself happens before any write, so no
   lock (in particular the audit chain's) is held while a model is thinking.

Proposals: the AI can only suggest an action from a fixed list. A lead approves or rejects it;
approving runs the action through its normal service, as the approving person, in the same
transaction as the decision, so either both happen or neither does. Every action is re-checked
at approval time (the event may have been linked since, the WAF rule switched to block, the
model archived). A proposal from an input with a high prompt-risk score needs a written reason
to approve. Nothing the AI proposes can loosen a control.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.ai import contract, guardrails
from app.ai.contract import AnalysisOutput, ContractError
from app.ai.guardrails import AnalysisInput, Pseudonyms
from app.ai.providers import Provider, ProviderError
from app.core.authz import Principal
from app.core.clock import utcnow
from app.core.config import AIProvider, Settings
from app.core.errors import ApiError
from app.core.provenance import Provenance
from app.models.ai import (
    AiAnalysis,
    AiProposal,
    AnalysisStatus,
    ProposalStatus,
    ProposalType,
    SubjectType,
)
from app.models.application import Application
from app.models.audit import AuditResult
from app.models.governance import (
    Control,
    ElementKind,
    ModelElement,
    ModelOrigin,
    ModelStatus,
    Threat,
    ThreatModel,
)
from app.models.incident import Incident
from app.models.risk_governance import ChangeType, RiskLevel
from app.models.security_event import EventCategory, SecurityEvent, Severity
from app.models.simulation import SimulatedWafRule, WafMode
from app.models.user import Role
from app.models.vulnerability import Vulnerability
from app.schemas.ai import (
    AiStatus,
    AnalysisDetail,
    AnalysisList,
    AnalysisRequest,
    AnalysisSummary,
    AppRef,
    Decision,
    ProposalCounts,
    ProposalDecision,
    ProposalList,
    ProposalOut,
    SubjectRef,
)
from app.schemas.ai import RiskLevel as InputRisk
from app.schemas.governance import ThreatCreate
from app.schemas.incidents import IncidentCreate
from app.schemas.risk_governance import ChangeCreate, WafTarget
from app.services import audit
from app.services.audit import AuditAction, RequestContext
from app.services.governance import GovernanceService, sync_catalogue
from app.services.incidents import IncidentService
from app.services.risk_governance import RiskGovernanceService
from app.services.simulator import waf_rule_ids

LEADS = frozenset({Role.ADMIN, Role.SECURITY_ENGINEER})
SEES_ALL = frozenset({Role.ADMIN, Role.SECURITY_ENGINEER, Role.ANALYST, Role.VIEWER})
ANALYSERS = frozenset({Role.ADMIN, Role.SECURITY_ENGINEER, Role.ANALYST, Role.DEVELOPER})
# Developers work on their own applications' findings and models; events and incidents are
# security operations data they do not see anywhere else either.
DEVELOPER_SUBJECTS = frozenset({SubjectType.VULNERABILITY, SubjectType.THREAT_MODEL})
WINDOW = timedelta(hours=24)
MAX_LIST = 100
_QUOTA_LOCK = 0x5E7E1A10000  # namespace for the per-user advisory lock (plus the user's hash)
_SEVERITY_RANK = {s: i for i, s in enumerate(Severity)}


def _risk_level(score: int) -> InputRisk:
    if score >= guardrails.HIGH_RISK:
        return InputRisk.HIGH
    if score >= guardrails.MEDIUM_RISK:
        return InputRisk.MEDIUM
    return InputRisk.LOW


@contextmanager
def one_transaction(db: Session) -> Iterator[None]:
    """Run another service's write inside the caller's transaction: its commit becomes a flush,
    so the action and the decision about it are committed together, or not at all."""
    real_commit = db.commit
    db.commit = db.flush  # type: ignore[method-assign]
    try:
        yield
    finally:
        db.commit = real_commit  # type: ignore[method-assign]


class AiService:
    def __init__(
        self, *, db: Session, ctx: RequestContext, settings: Settings, provider: Provider | None
    ) -> None:
        self.db = db
        self.ctx = ctx
        self.settings = settings
        self.provider = provider

    # --- access -----------------------------------------------------------------------------

    def _deny(self, principal: Principal, resource_type: str, resource_id: uuid.UUID) -> ApiError:
        audit.record(
            self.db,
            action=AuditAction.ACCESS_DENIED,
            result=AuditResult.DENIED,
            actor=principal.user,
            ctx=self.ctx,
            resource_type=resource_type,
            resource_id=str(resource_id),
            details={"reason": "not_owner"},
        )
        self.db.commit()
        return ApiError(404, "not_found", "Not Found")

    def _sees_app(self, principal: Principal, app_id: uuid.UUID | None) -> bool:
        if principal.user.role in SEES_ALL:
            return True
        if app_id is None:
            return False
        app = self.db.get(Application, app_id)
        return app is not None and app.owner_id == principal.user.id

    def _analysis(self, principal: Principal, analysis_id: uuid.UUID) -> AiAnalysis:
        a = self.db.get(AiAnalysis, analysis_id)
        if a is None:
            raise ApiError(404, "not_found", "Not Found")
        if not self._sees_app(principal, a.application_id):
            raise self._deny(principal, "ai_analysis", a.id)
        return a

    # --- building the input -----------------------------------------------------------------

    def _known_controls(self) -> frozenset[str]:
        sync_catalogue(self.db)
        return frozenset(self.db.scalars(select(Control.ref).where(~Control.retired)).all())

    def _waf_mode(self, rule_id: str) -> WafMode:
        stored = self.db.get(SimulatedWafRule, rule_id)
        return stored.mode if stored else WafMode.BLOCK

    def _event_input(self, e: SecurityEvent, p: Pseudonyms) -> tuple[dict[str, Any], set[Any]]:
        raw: dict[str, Any] = {
            "title": e.title,
            "source": e.source.value,
            "category": e.category.value,
            "severity": e.severity.value,
            "outcome": e.outcome.value,
            "method": e.method,
            "endpoint": e.endpoint,
            "status_code": e.status_code,
            "rule_id": e.rule_id,
            "user_agent": e.user_agent,
            "occurred_at": e.occurred_at.isoformat(),
            "client": p.client(e.source_ip) if e.source_ip else None,
            "actor": p.user(e.actor_label) if e.actor_label else None,
            "provenance": e.provenance.value,
        }
        for key, value in list((e.evidence or {}).items())[:20]:
            if isinstance(value, str | int | float):
                raw[f"evidence.{key}"[:40]] = value
        actions: set[Any] = set()
        if e.incident_id is None:
            actions.add(ProposalType.OPEN_INCIDENT)
        if e.rule_id in waf_rule_ids() and self._waf_mode(e.rule_id) is not WafMode.BLOCK:
            actions.add(ProposalType.RAISE_CHANGE_REQUEST)
        return raw, actions

    def _subject(
        self, principal: Principal, body: AnalysisRequest
    ) -> tuple[AnalysisInput, Provenance, uuid.UUID | None]:
        """The minimised input, the subject's provenance and its application."""
        if principal.user.role is Role.DEVELOPER and body.subject_type not in DEVELOPER_SUBJECTS:
            raise ApiError(403, "forbidden", "Developers analyse findings and threat models only.")
        p = Pseudonyms()
        st = body.subject_type
        raw: dict[str, Any]
        platform: dict[str, str]
        actions: set[Any] = set()
        waf_rule: str | None = None
        app_id: uuid.UUID | None = None
        provenance = Provenance.LOCAL
        if st is SubjectType.SECURITY_EVENT:
            e = self.db.scalar(select(SecurityEvent).where(SecurityEvent.id == body.subject_id))
            if e is None:
                raise ApiError(404, "not_found", "Not Found")
            raw, actions = self._event_input(e, p)
            ref = f"event {e.rule_id or e.category.value} {e.occurred_at:%Y-%m-%d %H:%M}"
            platform = {"category": e.category.value, "severity": e.severity.value}
            if ProposalType.RAISE_CHANGE_REQUEST in actions:
                waf_rule = e.rule_id
                platform["waf_rule"] = f"{e.rule_id} (simulated WAF, counting, not blocking)"
            provenance = e.provenance
        elif st is SubjectType.INCIDENT:
            inc = self.db.get(Incident, body.subject_id)
            if inc is None:
                raise ApiError(404, "not_found", "Not Found")
            events = self.db.scalars(
                select(SecurityEvent)
                .where(SecurityEvent.incident_id == inc.id)
                .order_by(SecurityEvent.occurred_at)
                .limit(10)
            ).all()
            raw = {
                "title": inc.title,
                "summary": inc.summary,
                "severity": inc.severity.value,
                "category": inc.category.value if inc.category else None,
                "status": inc.status.value,
                "detection_rule": inc.detection_rule,
                "client": p.client(inc.source_ip) if inc.source_ip else None,
                "remediation": inc.remediation,
                "provenance": inc.provenance.value,
            }
            for n, ev in enumerate(events, 1):
                raw[f"event_{n}.title"] = ev.title
                raw[f"event_{n}.endpoint"] = ev.endpoint
                raw[f"event_{n}.snippet"] = (ev.evidence or {}).get("snippet")
            ref = inc.reference
            platform = {
                "category": inc.category.value if inc.category else "unknown",
                "severity": inc.severity.value,
            }
            provenance = inc.provenance
        elif st is SubjectType.VULNERABILITY:
            v = self.db.get(Vulnerability, body.subject_id)
            if v is None:
                raise ApiError(404, "not_found", "Not Found")
            if not self._sees_app(principal, v.application_id):
                raise self._deny(principal, "vulnerability", v.id)
            raw = {
                "title": v.title,
                "tool": v.tool.value,
                "category": v.category.value,
                "rule_id": v.rule_id,
                "severity": v.severity.value,
                "component": v.component,
                "location": v.location,
                "cve": v.cve,
                "cvss": v.cvss,
                "fixed_version": v.fixed_version,
                "recommendation": v.recommendation,
                "status": v.status.value,
            }
            ref = v.reference
            category = {
                "sca": EventCategory.VULNERABLE_DEPENDENCY.value,
                "container": EventCategory.VULNERABLE_DEPENDENCY.value,
                "secret": EventCategory.EXPOSED_SECRET.value,
            }.get(v.category.value, EventCategory.CODE_WEAKNESS.value)
            platform = {"category": category, "severity": v.severity.value}
            app_id = v.application_id
        else:
            m = self.db.get(ThreatModel, body.subject_id)
            if m is None:
                raise ApiError(404, "not_found", "Not Found")
            if not self._sees_app(principal, m.application_id):
                raise self._deny(principal, "threat_model", m.id)
            elements = self.db.scalars(
                select(ModelElement).where(ModelElement.model_id == m.id, ~ModelElement.retired)
            ).all()
            threats = self.db.scalars(
                select(Threat)
                .where(Threat.model_id == m.id, ~Threat.retired)
                .order_by(Threat.ref)
                .limit(40)
            ).all()
            app = self.db.get(Application, m.application_id)

            def names(kind: ElementKind) -> str:
                return "; ".join(x.name for x in elements if x.kind is kind)[:400]

            raw = {
                "name": m.name,
                "method": m.method.value,
                "application": app.name if app else None,
                "scope": m.scope,
                "assets": names(ElementKind.ASSET),
                "boundaries": names(ElementKind.BOUNDARY),
                "flows": names(ElementKind.FLOW),
                "threats": "; ".join(f"{t.ref} [{t.stride}] {t.title}" for t in threats),
                "stride_covered": "".join(
                    sorted({c for t in threats for c in t.stride if c in "STRIDE"})
                ),
            }
            ref = m.reference
            platform = {"category": "design_threat", "severity": "medium"}
            if m.origin is ModelOrigin.APP and m.status is not ModelStatus.ARCHIVED:
                actions.add(ProposalType.ADD_THREAT)
            app_id = m.application_id
        fields, removed = guardrails.minimise(raw, p)
        inp = AnalysisInput(
            subject_type=st,
            subject_ref=ref,
            fields=fields,
            platform=platform,
            allowed_actions=frozenset(actions),
            waf_rule=waf_rule,
            removed_invisible=removed,
        )
        return inp, provenance, app_id

    # --- quotas -----------------------------------------------------------------------------

    def _usage(self, principal: Principal) -> tuple[int, int]:
        since = utcnow() - WINDOW
        mine = self.db.scalar(
            select(func.count())
            .select_from(AiAnalysis)
            .where(AiAnalysis.requested_by_id == principal.user.id, AiAnalysis.created_at > since)
        )
        tokens = self.db.scalar(
            select(
                func.coalesce(func.sum(AiAnalysis.input_tokens + AiAnalysis.output_tokens), 0)
            ).where(AiAnalysis.created_at > since)
        )
        return int(mine or 0), int(tokens or 0)

    def _check_quota(self, principal: Principal) -> None:
        # Serialise one user's analyses so two parallel requests cannot both pass the check.
        key = _QUOTA_LOCK + (principal.user.id.int % 0xFFFFFFFF)
        self.db.execute(select(func.pg_advisory_xact_lock(key)))
        mine, tokens = self._usage(principal)
        limit = None
        if mine >= self.settings.ai_requests_per_user_per_day:
            limit = f"{self.settings.ai_requests_per_user_per_day} analyses per user per day"
        elif tokens + self.settings.ai_max_output_tokens > self.settings.ai_tokens_per_day:
            limit = f"{self.settings.ai_tokens_per_day} tokens per day for the platform"
        if limit:
            self.db.rollback()
            audit.record(
                self.db,
                action=AuditAction.AI_QUOTA_EXCEEDED,
                result=AuditResult.DENIED,
                actor=principal.user,
                ctx=self.ctx,
                resource_type="ai_analysis",
                details={"limit": limit, "requests_today": mine, "platform_usage_today": tokens},
            )
            self.db.commit()
            raise ApiError(429, "ai_quota_exceeded", f"AI quota reached: {limit}.")

    # --- analyse ----------------------------------------------------------------------------

    def analyse(self, principal: Principal, body: AnalysisRequest) -> AnalysisDetail:
        if self.provider is None:
            raise ApiError(
                503,
                "ai_disabled",
                "AI analysis is switched off (SENTINEL_AI_PROVIDER=disabled).",
            )
        inp, provenance, app_id = self._subject(principal, body)
        known = self._known_controls()
        self._check_quota(principal)
        risk, signals = guardrails.score(inp)
        prompt = guardrails.build_prompt(inp)

        started = time.monotonic()
        output: AnalysisOutput | None = None
        failure: str | None = None
        status = AnalysisStatus.COMPLETED
        input_tokens = guardrails.estimate_tokens(prompt.system + prompt.user)
        output_tokens = 0
        try:
            completion = self.provider.complete(prompt, inp, self.settings.ai_max_output_tokens)
            input_tokens, output_tokens = completion.input_tokens, completion.output_tokens
            output = contract.validate(completion.text, inp, known)
        except ProviderError as exc:
            status, failure = AnalysisStatus.FAILED, str(exc)[:500]
        except ContractError as exc:
            status, failure = AnalysisStatus.REJECTED, str(exc)[:500]
        duration = int((time.monotonic() - started) * 1000)

        now = utcnow()
        analysis = AiAnalysis(
            id=uuid.uuid4(),
            subject_type=inp.subject_type,
            subject_id=body.subject_id,
            subject_ref=inp.subject_ref[:64],
            application_id=app_id,
            provenance=provenance,
            requested_by_id=principal.user.id,
            requested_by_label=principal.user.email,
            provider=self.provider.name,
            model=self.provider.model,
            status=status,
            failure=failure,
            prompt_risk=risk,
            risk_signals=signals,
            input_sha256=prompt.sha256,
            input_chars=prompt.chars,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            duration_ms=duration,
            output=output.model_dump(mode="json") if output else None,
            created_at=now,
        )
        self.db.add(analysis)
        self.db.flush()
        for action in output.proposed_actions if output else []:
            data = action.model_dump(mode="json")
            rationale = data.pop("rationale")
            self.db.add(
                AiProposal(
                    id=uuid.uuid4(),
                    analysis_id=analysis.id,
                    action_type=ProposalType(data["type"]),
                    payload=data,
                    rationale=rationale,
                    status=ProposalStatus.PROPOSED,
                    created_at=now,
                    version=1,
                )
            )
        self.db.flush()
        audit.record(
            self.db,
            action=AuditAction.AI_ANALYSIS_RUN,
            result=AuditResult.SUCCESS
            if status is AnalysisStatus.COMPLETED
            else AuditResult.FAILURE,
            actor=principal.user,
            ctx=self.ctx,
            resource_type="ai_analysis",
            resource_id=str(analysis.id),
            details={
                "analysis": analysis.reference,
                "subject": f"{inp.subject_type.value}:{inp.subject_ref}",
                "provider": self.provider.name,
                "model": self.provider.model,
                "status": status.value,
                "prompt_risk": risk,
                "risk_signals": signals,
                # Not "tokens": the audit log redacts keys that look like credentials.
                "usage": {"input": input_tokens, "output": output_tokens},
                "input_sha256": prompt.sha256,
                "proposals": len(output.proposed_actions) if output else 0,
            },
        )
        self.db.commit()
        return self._detail(principal, analysis)

    # --- presentation -----------------------------------------------------------------------

    def _app_ref(self, app_id: uuid.UUID | None) -> AppRef | None:
        app = self.db.get(Application, app_id) if app_id else None
        return AppRef(id=app.id, slug=app.slug, name=app.name) if app else None

    @staticmethod
    def _subject_ref(a: AiAnalysis) -> SubjectRef:
        return SubjectRef(type=a.subject_type, id=a.subject_id, reference=a.subject_ref)

    def _summary(self, a: AiAnalysis, proposals: int) -> AnalysisSummary:
        out = a.output or {}
        return AnalysisSummary(
            id=a.id,
            reference=a.reference,
            subject=self._subject_ref(a),
            application=self._app_ref(a.application_id),
            provenance=a.provenance,
            status=a.status,
            provider=a.provider,
            model=a.model,
            prompt_risk=a.prompt_risk,
            risk_level=_risk_level(a.prompt_risk),
            classification=out.get("classification"),
            severity=out.get("severity"),
            proposals=proposals,
            requested_by_label=a.requested_by_label,
            created_at=a.created_at,
        )

    def _proposal(self, principal: Principal, p: AiProposal, a: AiAnalysis) -> ProposalOut:
        pending = p.status is ProposalStatus.PROPOSED
        return ProposalOut(
            id=p.id,
            reference=p.reference,
            analysis_id=a.id,
            analysis_reference=a.reference,
            subject=self._subject_ref(a),
            action_type=p.action_type,
            payload=p.payload,
            rationale=p.rationale,
            status=p.status,
            input_risk=a.prompt_risk,
            note_required=pending and a.prompt_risk >= guardrails.HIGH_RISK,
            can_decide=pending and principal.user.role in LEADS,
            decided_by_label=p.decided_by_label,
            decided_at=p.decided_at,
            decision_note=p.decision_note,
            result_ref=p.result_ref,
            created_at=p.created_at,
            version=p.version,
        )

    def _platform_verdict(self, a: AiAnalysis) -> tuple[str | None, Severity | None]:
        if a.subject_type is SubjectType.SECURITY_EVENT:
            e = self.db.scalar(select(SecurityEvent).where(SecurityEvent.id == a.subject_id))
            return (e.category.value, e.severity) if e else (None, None)
        if a.subject_type is SubjectType.INCIDENT:
            inc = self.db.get(Incident, a.subject_id)
            if inc:
                return (inc.category.value if inc.category else None, inc.severity)
        if a.subject_type is SubjectType.VULNERABILITY:
            v = self.db.get(Vulnerability, a.subject_id)
            return (None, v.severity) if v else (None, None)
        return None, None

    def _disagreements(self, a: AiAnalysis) -> list[str]:
        if not a.output:
            return []
        out: list[str] = []
        category, severity = self._platform_verdict(a)
        ai_severity = Severity(a.output["severity"])
        if severity is not None and _SEVERITY_RANK[ai_severity] < _SEVERITY_RANK[severity]:
            out.append(
                f"The AI rates this {ai_severity.value}; the platform rated it "
                f"{severity.value}. The platform's rating stands."
            )
        if category and a.output["classification"] == "benign":
            out.append(
                f"The AI calls this benign; the platform detected {category.replace('_', ' ')}."
            )
        return out

    def _detail(self, principal: Principal, a: AiAnalysis) -> AnalysisDetail:
        proposals = self.db.scalars(
            select(AiProposal).where(AiProposal.analysis_id == a.id).order_by(AiProposal.number)
        ).all()
        summary = self._summary(a, len(proposals))
        return AnalysisDetail(
            **summary.model_dump(),
            failure=a.failure,
            risk_signals=a.risk_signals,
            input_sha256=a.input_sha256,
            input_chars=a.input_chars,
            input_tokens=a.input_tokens,
            output_tokens=a.output_tokens,
            duration_ms=a.duration_ms,
            output=AnalysisOutput.model_validate_json(json.dumps(a.output)) if a.output else None,
            disagreements=self._disagreements(a),
            proposal_items=[self._proposal(principal, p, a) for p in proposals],
        )

    # --- reads ------------------------------------------------------------------------------

    def _visible(self, principal: Principal, query: Any) -> Any:
        if principal.user.role in SEES_ALL:
            return query
        own = select(Application.id).where(Application.owner_id == principal.user.id)
        return query.where(AiAnalysis.application_id.in_(own))

    def list_analyses(
        self,
        principal: Principal,
        subject_type: SubjectType | None,
        subject_id: uuid.UUID | None,
    ) -> AnalysisList:
        query = select(AiAnalysis)
        if subject_type is not None:
            query = query.where(AiAnalysis.subject_type == subject_type)
        if subject_id is not None:
            query = query.where(AiAnalysis.subject_id == subject_id)
        rows = self.db.scalars(
            self._visible(principal, query).order_by(AiAnalysis.number.desc()).limit(MAX_LIST)
        ).all()
        counts = dict(
            self.db.execute(
                select(AiProposal.analysis_id, func.count())
                .where(AiProposal.analysis_id.in_([a.id for a in rows]))
                .group_by(AiProposal.analysis_id)
            ).all()
        )
        return AnalysisList(items=[self._summary(a, int(counts.get(a.id, 0))) for a in rows])

    def get_analysis(self, principal: Principal, analysis_id: uuid.UUID) -> AnalysisDetail:
        return self._detail(principal, self._analysis(principal, analysis_id))

    def list_proposals(self, principal: Principal, status: ProposalStatus | None) -> ProposalList:
        query = select(AiProposal, AiAnalysis).join(
            AiAnalysis, AiAnalysis.id == AiProposal.analysis_id
        )
        query = self._visible(principal, query)
        counts = {s: 0 for s in ProposalStatus}
        for s, n in self.db.execute(
            self._visible(
                principal,
                select(AiProposal.status, func.count())
                .join(AiAnalysis, AiAnalysis.id == AiProposal.analysis_id)
                .group_by(AiProposal.status),
            )
        ).all():
            counts[ProposalStatus(s)] = int(n)
        if status is not None:
            query = query.where(AiProposal.status == status)
        rows = self.db.execute(query.order_by(AiProposal.number.desc()).limit(MAX_LIST)).all()
        return ProposalList(
            items=[self._proposal(principal, p, a) for p, a in rows],
            counts=ProposalCounts(
                proposed=counts[ProposalStatus.PROPOSED],
                approved=counts[ProposalStatus.APPROVED],
                rejected=counts[ProposalStatus.REJECTED],
            ),
        )

    def status(self, principal: Principal) -> AiStatus:
        mine, tokens = self._usage(principal)
        enabled = self.provider is not None
        bedrock = self.settings.ai_provider is AIProvider.BEDROCK
        return AiStatus(
            enabled=enabled,
            provider=self.settings.ai_provider.value,
            model=self.provider.model if self.provider else None,
            provenance=(Provenance.REAL_AWS if bedrock else Provenance.LOCAL) if enabled else None,
            can_analyse=enabled and principal.user.role in ANALYSERS,
            requests_today=mine,
            requests_per_day=self.settings.ai_requests_per_user_per_day,
            tokens_today=tokens,
            tokens_per_day=self.settings.ai_tokens_per_day,
            max_output_tokens=self.settings.ai_max_output_tokens,
        )

    # --- decisions --------------------------------------------------------------------------

    def _execute(self, principal: Principal, p: AiProposal, a: AiAnalysis) -> str:
        """Run an approved action through its own service, as the approving person."""
        payload = p.payload
        origin = f"AI proposal {p.reference} (analysis {a.reference})"
        if p.action_type is ProposalType.OPEN_INCIDENT:
            event = self.db.scalar(select(SecurityEvent).where(SecurityEvent.id == a.subject_id))
            if event is None:
                raise ApiError(409, "subject_gone", "The event no longer exists.")
            incident = IncidentService(db=self.db, ctx=self.ctx).create(
                principal,
                IncidentCreate(
                    title=payload["title"],
                    summary=f"Opened from {origin}: {p.rationale}"[:2000],
                    severity=Severity(payload["severity"]),
                    category=event.category,
                    event_ids=[event.id],
                ),
            )
            return incident.reference
        if p.action_type is ProposalType.RAISE_CHANGE_REQUEST:
            rule = payload["rule_id"]
            if self._waf_mode(rule) is WafMode.BLOCK:
                raise ApiError(409, "already_blocking", f"Rule {rule} already blocks.")
            change = RiskGovernanceService(db=self.db, ctx=self.ctx).submit_change(
                principal,
                ChangeCreate(
                    title=f"Block simulated WAF rule {rule} ({p.reference})",
                    change_type=ChangeType.WAF_RULE,
                    description=f"Raised from {origin}: {p.rationale}"[:4000],
                    risk_level=RiskLevel.MEDIUM,
                    impact=f"Requests matching {rule} are refused at the simulated edge instead "
                    "of counted; a legitimate request that matches would be refused too.",
                    rollback_plan=f"Roll back this change request: {rule} returns to its "
                    "previous mode.",
                    validation_plan=f"Run the matching attack simulation and confirm {rule} "
                    "now blocks it.",
                    target=WafTarget(rule_id=rule, mode=WafMode.BLOCK),
                ),
            )
            return change.reference
        model = GovernanceService(db=self.db, ctx=self.ctx).add_threat(
            principal,
            a.subject_id,
            ThreatCreate(
                title=payload["title"],
                stride=payload["stride"],
                likelihood=payload["likelihood"],
                impact=payload["impact"],
                mitigation=f"Suggested by {origin}: {p.rationale}"[:4000],
                controls=payload["controls"],
            ),
        )
        added = max((t for t in model.threats if t.title == payload["title"]), key=lambda t: t.ref)
        return f"{model.reference}/{added.ref}"

    def decide(
        self, principal: Principal, proposal_id: uuid.UUID, body: ProposalDecision
    ) -> ProposalOut:
        p = self.db.get(AiProposal, proposal_id, with_for_update=True)
        if p is None:
            raise ApiError(404, "not_found", "Not Found")
        a = self._analysis(principal, p.analysis_id)
        if p.status is not ProposalStatus.PROPOSED:
            raise ApiError(409, "already_decided", f"{p.reference} has already been decided.")
        if p.version != body.version:
            raise ApiError(409, "stale_version", "The proposal changed since you loaded it.")
        approve = body.decision is Decision.APPROVE
        if not approve and not body.note:
            raise ApiError(422, "note_required", "Explain the rejection in a note.")
        if approve and a.prompt_risk >= guardrails.HIGH_RISK and not body.note:
            raise ApiError(
                422,
                "note_required",
                "The input behind this proposal scored high for prompt injection: explain why "
                "the action is right anyway.",
            )
        result_ref: str | None = None
        try:
            if approve:
                with one_transaction(self.db):
                    result_ref = self._execute(principal, p, a)
            now = utcnow()
            p.status = ProposalStatus.APPROVED if approve else ProposalStatus.REJECTED
            p.decided_by_id = principal.user.id
            p.decided_by_label = principal.user.email
            p.decided_at = now
            p.decision_note = body.note
            p.result_ref = result_ref
            p.version += 1
            audit.record(
                self.db,
                action=AuditAction.AI_PROPOSAL_APPROVED
                if approve
                else AuditAction.AI_PROPOSAL_REJECTED,
                result=AuditResult.SUCCESS,
                actor=principal.user,
                ctx=self.ctx,
                resource_type="ai_proposal",
                resource_id=str(p.id),
                details={
                    "proposal": p.reference,
                    "analysis": a.reference,
                    "action": p.action_type.value,
                    "result": result_ref,
                    "input_risk": a.prompt_risk,
                    "note": body.note,
                },
            )
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise
        return self._proposal(principal, p, a)
