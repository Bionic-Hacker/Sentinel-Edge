"""The edge in AWS, read back into SentinelEdge (Phase 5, ADR-0029).

Two read-only feeds, both off unless configured (they exist only in a deployed environment):

* **AWS WAF blocks.** Every request AWS WAF blocks is logged to CloudWatch Logs in us-east-1
  (ADR-0027). The API reads new BLOCK records and stores each as a security event with
  provenance REAL_AWS, source `waf`, outcome `blocked`, so it appears on the Threats page next
  to labelled simulated events and goes through correlation like any other event.
* **ACM certificates.** The certificates in the configured Regions, read live for the
  Certificates page, and checked on every sync: one that is expiring, expired, revoked or failed
  renewal raises a certificate event (once per certificate, condition and day).

Both run on a timer inside the API (`aws_sync_interval_seconds`) and on demand ("Sync now").
Records read from outside carry `evidence.dedupe_key`; a unique index (migration 0016) stores
each once, however often or by however many tasks it is read.

The API's role may only read: logs:FilterLogEvents on the one WAF log group, and
acm:ListCertificates / acm:DescribeCertificate. It can change nothing in WAF or ACM.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.clock import utcnow
from app.core.config import Settings
from app.core.provenance import Provenance
from app.models.security_event import (
    EventCategory,
    EventSource,
    Outcome,
    SecurityEvent,
    Severity,
)
from app.services import security_events

logger = logging.getLogger("sentineledge.aws_edge")

C = EventCategory
S = Severity
# How far back the first sync looks, and the overlap kept between syncs (late log delivery).
FIRST_LOOKBACK = timedelta(hours=24)
OVERLAP = timedelta(minutes=5)
# Bounds the work one sync does; the rest is picked up by the next one.
MAX_WAF_RECORDS = 1000
CERTIFICATE_CACHE_SECONDS = 300
EXPIRY_WARNING_DAYS = 30
KEY_TYPES = [
    "RSA_1024",
    "RSA_2048",
    "RSA_3072",
    "RSA_4096",
    "EC_prime256v1",
    "EC_secp384r1",
    "EC_secp521r1",
]

ClientFactory = Callable[[str, str], Any]


def boto3_client(service: str, region: str) -> Any:
    # Imported here so boto3 loads only where AWS is configured.
    import boto3
    from botocore.config import Config

    return boto3.client(
        service,
        region_name=region,
        config=Config(
            retries={"max_attempts": 3, "mode": "standard"},
            connect_timeout=5,
            read_timeout=15,
            user_agent_extra="sentineledge",
        ),
    )


# Replaced in tests with fakes; boto3 in a deployed environment.
_client_factory: ClientFactory = boto3_client


def reset_cache() -> None:
    global _cache
    with _cache_lock:
        _cache = None


# --- WAF records ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WafMapping:
    category: EventCategory
    severity: Severity
    label: str


# Keyed by the web ACL rule names in terraform/modules/waf; managed sub-rules refine it.
_WAF_RULES: dict[str, WafMapping] = {
    "ip-reputation": WafMapping(C.BOT, S.LOW, "a request from a known-bad address"),
    "core-rule-set": WafMapping(C.API_ABUSE, S.LOW, "a request matching the core rule set"),
    "known-bad-inputs": WafMapping(C.RECON, S.LOW, "a known-bad input"),
    "sql-injection": WafMapping(C.SQL_INJECTION, S.MEDIUM, "an SQL injection"),
    "body-too-large": WafMapping(C.API_ABUSE, S.LOW, "an oversized request body"),
    "sign-in-rate": WafMapping(C.RATE_LIMIT, S.MEDIUM, "sign-in attempts over the rate limit"),
    "api-rate": WafMapping(C.RATE_LIMIT, S.MEDIUM, "API requests over the rate limit"),
}
# Managed sub-rule name prefixes that say more than the rule group does.
_SUB_RULES: tuple[tuple[str, WafMapping], ...] = (
    ("CrossSiteScripting", WafMapping(C.XSS, S.MEDIUM, "a cross-site scripting payload")),
    ("GenericLFI", WafMapping(C.PATH_TRAVERSAL, S.MEDIUM, "a path traversal")),
    ("RestrictedExtensions", WafMapping(C.PATH_TRAVERSAL, S.LOW, "a restricted file request")),
    ("GenericRFI", WafMapping(C.SSRF, S.MEDIUM, "a remote file inclusion")),
    ("EC2MetaDataSSRF", WafMapping(C.SSRF, S.MEDIUM, "an SSRF attempt")),
    ("NoUserAgent", WafMapping(C.SCANNER, S.LOW, "a request without a user agent")),
    ("UserAgent_BadBots", WafMapping(C.SCANNER, S.LOW, "a known scanner")),
    ("SizeRestrictions", WafMapping(C.API_ABUSE, S.LOW, "an oversized request part")),
    ("Log4JRCE", WafMapping(C.COMMAND_INJECTION, S.MEDIUM, "a Log4j (JNDI) exploit attempt")),
    ("JavaDeserialization", WafMapping(C.COMMAND_INJECTION, S.MEDIUM, "a Java exploit attempt")),
    ("SQLi", WafMapping(C.SQL_INJECTION, S.MEDIUM, "an SQL injection")),
)
_DEFAULT_MAPPING = WafMapping(C.API_ABUSE, S.LOW, "a request")


@dataclass(frozen=True)
class WafRecord:
    event_id: str
    occurred_at: datetime
    rule: str
    managed_rule: str | None
    mapping: WafMapping
    client_ip: str | None
    country: str | None
    method: str | None
    uri: str | None
    args: str | None
    user_agent: str | None
    request_id: str | None
    labels: list[str]


def parse_waf_record(event_id: str, message: str) -> WafRecord | None:
    """One AWS WAF log record, or None if it is not a BLOCK we can read."""
    try:
        data = json.loads(message)
    except ValueError:
        return None
    if not isinstance(data, dict) or data.get("action") != "BLOCK":
        return None
    rule = str(data.get("terminatingRuleId") or "unknown")
    managed_rule = None
    for group in data.get("ruleGroupList") or []:
        terminating = group.get("terminatingRule") if isinstance(group, dict) else None
        if isinstance(terminating, dict) and terminating.get("ruleId"):
            managed_rule = str(terminating["ruleId"])
            break
    mapping = _WAF_RULES.get(rule, _DEFAULT_MAPPING)
    if managed_rule:
        mapping = next((m for p, m in _SUB_RULES if managed_rule.startswith(p)), mapping)
    raw_request = data.get("httpRequest")
    request: dict[str, Any] = raw_request if isinstance(raw_request, dict) else {}
    raw_headers = request.get("headers")
    headers: list[Any] = raw_headers if isinstance(raw_headers, list) else []
    user_agent = next(
        (
            str(h.get("value"))
            for h in headers
            if isinstance(h, dict) and str(h.get("name", "")).lower() == "user-agent"
        ),
        None,
    )
    try:
        occurred_at = datetime.fromtimestamp(int(data["timestamp"]) / 1000, UTC)
    except (KeyError, TypeError, ValueError):
        return None
    labels = [
        str(item.get("name"))
        for item in data.get("labels") or []
        if isinstance(item, dict) and item.get("name")
    ]
    return WafRecord(
        event_id=event_id,
        occurred_at=occurred_at,
        rule=rule,
        managed_rule=managed_rule,
        mapping=mapping,
        client_ip=request.get("clientIp"),
        country=request.get("country"),
        method=request.get("httpMethod"),
        uri=request.get("uri"),
        args=request.get("args") or None,
        user_agent=user_agent,
        request_id=request.get("requestId"),
        labels=labels,
    )


def _store(db: Session, record: Callable[[], SecurityEvent]) -> bool:
    """Store one externally read event once. False if it was already stored."""
    try:
        with db.begin_nested():
            record()
    except IntegrityError:
        return False
    return True


def _known_keys(db: Session, keys: list[str]) -> set[str]:
    if not keys:
        return set()
    column = SecurityEvent.evidence["dedupe_key"].astext
    return set(db.scalars(select(column).where(column.in_(keys))).all())


def _waf_start(db: Session, now: datetime) -> datetime:
    latest = db.scalar(
        select(func.max(SecurityEvent.occurred_at)).where(
            SecurityEvent.source == EventSource.WAF,
            SecurityEvent.provenance == Provenance.REAL_AWS,
        )
    )
    floor = now - FIRST_LOOKBACK
    return floor if latest is None else max(floor, latest - OVERLAP)


def _waf_log_events(
    client: Any, group: str, start: datetime, end: datetime
) -> Iterator[dict[str, Any]]:
    kwargs: dict[str, Any] = {
        "logGroupName": group,
        "startTime": int(start.timestamp() * 1000),
        "endTime": int(end.timestamp() * 1000),
        "filterPattern": '{ $.action = "BLOCK" }',
        "limit": 500,
    }
    while True:
        page = client.filter_log_events(**kwargs)
        yield from page.get("events", [])
        token = page.get("nextToken")
        if not token:
            return
        kwargs["nextToken"] = token


def ingest_waf_blocks(db: Session, settings: Settings, clients: ClientFactory) -> tuple[int, int]:
    """Read new AWS WAF blocks into security events. Returns (read, newly stored)."""
    if not settings.waf_log_group:
        return 0, 0
    now = utcnow()
    client = clients("logs", settings.waf_log_region)
    records: list[WafRecord] = []
    for raw in _waf_log_events(client, settings.waf_log_group, _waf_start(db, now), now):
        parsed = parse_waf_record(str(raw.get("eventId", "")), str(raw.get("message", "")))
        if parsed is not None and parsed.event_id:
            records.append(parsed)
        if len(records) >= MAX_WAF_RECORDS:
            break
    known = _known_keys(db, [f"waf:{r.event_id}" for r in records])
    stored = 0
    for r in sorted(records, key=lambda r: r.occurred_at):
        key = f"waf:{r.event_id}"
        if key in known:
            continue
        rule_name = r.managed_rule or r.rule

        def add(r: WafRecord = r, key: str = key, rule_name: str = rule_name) -> SecurityEvent:
            return security_events.record_event(
                db,
                source=EventSource.WAF,
                category=r.mapping.category,
                severity=r.mapping.severity,
                outcome=Outcome.BLOCKED,
                title=f"AWS WAF blocked {r.mapping.label} ({rule_name})",
                rule_id=rule_name,
                provenance=Provenance.REAL_AWS,
                occurred_at=r.occurred_at,
                ctx=security_events.EventContext(
                    source_ip=r.client_ip,
                    user_agent=r.user_agent,
                    method=r.method,
                    endpoint=r.uri,
                ),
                evidence={
                    "dedupe_key": key,
                    "web_acl_rule": r.rule,
                    "managed_rule": r.managed_rule,
                    "action": "BLOCK",
                    "country": r.country,
                    "uri": r.uri,
                    "query": r.args,
                    "labels": r.labels,
                    "request_id": r.request_id,
                    "log_group": settings.waf_log_group,
                },
            )

        if _store(db, add):
            stored += 1
    db.commit()
    return len(records), stored


# --- Certificates --------------------------------------------------------------------------


@dataclass(frozen=True)
class Certificate:
    arn: str
    region: str
    domain: str
    alternative_names: list[str]
    status: str
    type: str
    key_algorithm: str | None
    issuer: str | None
    not_before: datetime | None
    not_after: datetime | None
    renewal_eligibility: str | None
    renewal_status: str | None
    in_use_by: int

    def days_left(self, now: datetime) -> int | None:
        if self.not_after is None:
            return None
        return int((self.not_after - now).total_seconds() // 86400)

    def condition(self, now: datetime) -> tuple[str, Severity] | None:
        """Why this certificate needs attention, and how badly; None if it does not."""
        if self.status in {"EXPIRED", "REVOKED", "FAILED", "VALIDATION_TIMED_OUT"}:
            return self.status.lower(), S.CRITICAL
        if self.renewal_status == "FAILED":
            return "renewal_failed", S.HIGH
        days = self.days_left(now)
        if self.status == "ISSUED" and days is not None:
            if days < 0:
                return "expired", S.CRITICAL
            if days <= 14:
                return "expiring", S.HIGH
            if days <= EXPIRY_WARNING_DAYS:
                return "expiring", S.MEDIUM
        return None


def _describe(client: Any, region: str, arn: str) -> Certificate:
    detail = client.describe_certificate(CertificateArn=arn)["Certificate"]
    renewal = detail.get("RenewalSummary") or {}
    return Certificate(
        arn=arn,
        region=region,
        domain=str(detail.get("DomainName", "")),
        alternative_names=[str(n) for n in detail.get("SubjectAlternativeNames") or []],
        status=str(detail.get("Status", "UNKNOWN")),
        type=str(detail.get("Type", "UNKNOWN")),
        key_algorithm=detail.get("KeyAlgorithm"),
        issuer=detail.get("Issuer"),
        not_before=detail.get("NotBefore"),
        not_after=detail.get("NotAfter"),
        renewal_eligibility=detail.get("RenewalEligibility"),
        renewal_status=renewal.get("RenewalStatus"),
        in_use_by=len(detail.get("InUseBy") or []),
    )


def read_certificates(settings: Settings, clients: ClientFactory) -> list[Certificate]:
    found: list[Certificate] = []
    for region in settings.certificate_regions:
        client = clients("acm", region)
        kwargs: dict[str, Any] = {"Includes": {"keyTypes": KEY_TYPES}}
        while True:
            page = client.list_certificates(**kwargs)
            for summary in page.get("CertificateSummaryList", []):
                found.append(_describe(client, region, str(summary["CertificateArn"])))
            token = page.get("NextToken")
            if not token:
                break
            kwargs["NextToken"] = token
    return sorted(found, key=lambda c: (c.not_after or datetime.max.replace(tzinfo=UTC), c.arn))


_cache_lock = threading.Lock()
_cache: tuple[float, tuple[str, ...], list[Certificate]] | None = None


def certificates(
    settings: Settings, clients: ClientFactory | None = None, *, refresh: bool = False
) -> list[Certificate]:
    """The certificates, read from ACM at most once per CERTIFICATE_CACHE_SECONDS."""
    global _cache
    clients = clients or _client_factory
    regions = tuple(settings.certificate_regions)
    with _cache_lock:
        if (
            not refresh
            and _cache is not None
            and _cache[1] == regions
            and time.monotonic() - _cache[0] < CERTIFICATE_CACHE_SECONDS
        ):
            return _cache[2]
    found = read_certificates(settings, clients)
    with _cache_lock:
        _cache = (time.monotonic(), regions, found)
    return found


def check_certificates(db: Session, found: list[Certificate]) -> int:
    """Raise one certificate event per certificate, condition and day. Returns events stored."""
    now = utcnow()
    day = now.date().isoformat()
    pending = [(c, cond) for c in found if (cond := c.condition(now)) is not None]
    known = _known_keys(db, [f"cert:{c.arn}:{cond[0]}:{day}" for c, cond in pending])
    stored = 0
    for cert, (condition, severity) in pending:
        key = f"cert:{cert.arn}:{condition}:{day}"
        if key in known:
            continue
        days = cert.days_left(now)
        what = {
            "expiring": f"expires in {days} days",
            "expired": "has expired",
            "renewal_failed": "failed to renew",
        }.get(condition, f"is {condition.replace('_', ' ')}")

        def add(
            cert: Certificate = cert,
            key: str = key,
            condition: str = condition,
            severity: Severity = severity,
            what: str = what,
            days: int | None = days,
        ) -> SecurityEvent:
            return security_events.record_event(
                db,
                source=EventSource.CERTIFICATE,
                category=C.CERTIFICATE,
                severity=severity,
                outcome=Outcome.DETECTED,
                title=f"Certificate for {cert.domain} {what}",
                rule_id=f"ACM-{condition.upper()}"[:32],
                provenance=Provenance.REAL_AWS,
                ctx=security_events.EventContext(),
                evidence={
                    "dedupe_key": key,
                    "certificate_arn": cert.arn,
                    "region": cert.region,
                    "domain": cert.domain,
                    "status": cert.status,
                    "renewal_status": cert.renewal_status,
                    "not_after": cert.not_after.isoformat() if cert.not_after else None,
                    "days_left": days,
                },
            )

        if _store(db, add):
            stored += 1
    db.commit()
    return stored


# --- Sync ----------------------------------------------------------------------------------


@dataclass
class SyncStatus:
    started_at: datetime | None = None
    finished_at: datetime | None = None
    waf_records_read: int = 0
    waf_events_stored: int = 0
    certificates_checked: int = 0
    certificate_events_stored: int = 0
    # Generic on purpose: the exception class, never AWS's message (it can name resources).
    errors: list[str] = field(default_factory=list)


_status_lock = threading.Lock()
_status = SyncStatus()
_running = threading.Lock()


def last_sync() -> SyncStatus:
    with _status_lock:
        return SyncStatus(**vars(_status))


def sync(
    session_factory: Callable[[], Session],
    settings: Settings,
    clients: ClientFactory | None = None,
) -> SyncStatus:
    """Pull WAF blocks and check certificates. One sync at a time per process."""
    global _status
    clients = clients or _client_factory
    if not _running.acquire(blocking=False):
        return last_sync()
    try:
        result = SyncStatus(started_at=utcnow())
        if settings.waf_log_group:
            try:
                with session_factory() as db:
                    result.waf_records_read, result.waf_events_stored = ingest_waf_blocks(
                        db, settings, clients
                    )
            except Exception as exc:  # one feed failing must not stop the other
                logger.warning("waf_ingest_failed", extra={"error_type": type(exc).__name__})
                result.errors.append(f"WAF logs: {type(exc).__name__}")
        if settings.certificate_regions:
            try:
                found = certificates(settings, clients, refresh=True)
                result.certificates_checked = len(found)
                with session_factory() as db:
                    result.certificate_events_stored = check_certificates(db, found)
            except Exception as exc:
                logger.warning("certificate_check_failed", extra={"error_type": type(exc).__name__})
                result.errors.append(f"Certificates: {type(exc).__name__}")
        result.finished_at = utcnow()
        logger.info(
            "aws_edge_synced",
            extra={
                "waf_records_read": result.waf_records_read,
                "waf_events_stored": result.waf_events_stored,
                "certificates_checked": result.certificates_checked,
                "certificate_events_stored": result.certificate_events_stored,
                "errors": len(result.errors),
            },
        )
        with _status_lock:
            _status = result
        return SyncStatus(**vars(result))
    finally:
        _running.release()
