"""HTTP request analysis: attack-pattern detection for security operations (spec §12, Phase 7).

This is a DETECTION control, not a blocking one. It inspects the parts of a request an attacker
controls (path, query string, JSON body, User-Agent, Referer) for signatures of SQL injection,
XSS, path traversal, command injection, SSRF, known scanners and reconnaissance, and reports
what it found. Requests are still stopped by the controls that already exist (strict request
models, parameterized queries, output encoding, authorization) and, from Phase 5, by AWS WAF at
the edge. Detection tells the security team that someone tried.

Design rules:
* Pure functions over bounded input: at most 2 KiB of path, 8 KiB of query, 32 KiB of body.
* Values are percent-decoded up to twice (double encoding is a classic evasion) and lowercased
  before matching; evidence snippets are cut from the decoded value.
* Fields whose names look sensitive (password, token, secret, code...) are inspected like any
  other, but their content never appears in evidence: the snippet reads "[REDACTED]".
* Evidence snippets are bounded and stripped of control characters; the UI renders them as
  text only.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, unquote_plus

from app.models.security_event import EventCategory, Severity

MAX_PATH = 2048
MAX_QUERY = 8192
MAX_BODY = 32768
MAX_HEADER = 512
SNIPPET_CONTEXT = 30
SNIPPET_MAX = 160
REDACTED = "[REDACTED]"

_SENSITIVE_FIELD = re.compile(
    r"pass(word|wd|phrase)?|secret|token|api[_-]?key|authorization|cookie|credential|"
    r"private[_-]?key|session|^code$|recovery",
    re.IGNORECASE,
)
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class Location:
    PATH = "path"
    QUERY = "query"
    BODY = "body"
    USER_AGENT = "user_agent"
    REFERER = "referer"


INJECTABLE = (Location.PATH, Location.QUERY, Location.BODY, Location.REFERER)
# SSRF needs a value the server might fetch. A Referer naming an internal origin is normal
# (the SPA runs on localhost locally), and the server never fetches it.
FETCHABLE = (Location.PATH, Location.QUERY, Location.BODY)


@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: EventCategory
    severity: Severity
    description: str
    pattern: re.Pattern[str]
    locations: tuple[str, ...] = INJECTABLE
    unmatched_routes_only: bool = False


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.DOTALL)


# Whitespace, "+" or a complete /* comment */ between SQL keywords. The comment pattern cannot
# overlap itself and the quantifier is possessive (Python 3.11+): no catastrophic backtracking
# on inputs like "union /**/ /**/ ... x" (tests/unit/test_http_analysis_performance.py).
_SQL_GAP = r"(?:\s|/\*[^*]*\*+(?:[^/*][^*]*\*+)*/|\+)++"

RULES: tuple[Rule, ...] = (
    # --- SQL injection ------------------------------------------------------------------------
    Rule(
        "SQLI-001",
        EventCategory.SQL_INJECTION,
        Severity.HIGH,
        "UNION-based query extension",
        _rx(rf"\bunion{_SQL_GAP}(?:all{_SQL_GAP})?select\b"),
    ),
    Rule(
        "SQLI-002",
        EventCategory.SQL_INJECTION,
        Severity.HIGH,
        "Boolean tautology after a closing quote (' OR 1=1)",
        _rx(r"['\"`]\s*(?:or|and)\s+['\"`(]?\w+['\"`)]?\s*(?:=|<|>|like)\s*['\"`(]?\w+"),
    ),
    Rule(
        "SQLI-003",
        EventCategory.SQL_INJECTION,
        Severity.HIGH,
        "Quote followed by a comment that truncates the query (admin'--)",
        _rx(r"['\"`]\s*+\)?\s*+;?\s*+(?:--|#|/\*)(?:\s|$)"),
    ),
    Rule(
        "SQLI-004",
        EventCategory.SQL_INJECTION,
        Severity.HIGH,
        "Stacked query (; DROP ...)",
        _rx(r";\s*(?:drop|delete|insert|update|alter|create|truncate|exec(?:ute)?|shutdown)\s+\w"),
    ),
    Rule(
        "SQLI-005",
        EventCategory.SQL_INJECTION,
        Severity.HIGH,
        "Time-based blind probe (SLEEP, PG_SLEEP, WAITFOR DELAY)",
        _rx(r"\b(?:pg_sleep|sleep|benchmark)\s*\(|\bwaitfor\s+delay\s+'"),
    ),
    Rule(
        "SQLI-006",
        EventCategory.SQL_INJECTION,
        Severity.HIGH,
        "Database fingerprinting or file access (information_schema, @@version, INTO OUTFILE)",
        _rx(
            r"\binformation_schema\b|\bxp_cmdshell\b|@@version|\bload_file\s*\(|\binto\s+(?:out|dump)file\b"
        ),
    ),
    # --- Cross-site scripting -----------------------------------------------------------------
    Rule("XSS-001", EventCategory.XSS, Severity.MEDIUM, "Script tag", _rx(r"<\s*script\b")),
    Rule(
        "XSS-002",
        EventCategory.XSS,
        Severity.MEDIUM,
        "HTML tag with an event handler (onerror=, onload=)",
        # Bounded tag length: unbounded [^>]* is quadratic over many "<" characters.
        _rx(r"<[a-z][^>]{0,256}?\bon[a-z]{3,20}\s*+="),
    ),
    Rule(
        "XSS-003",
        EventCategory.XSS,
        Severity.MEDIUM,
        "Script URI scheme (javascript:, vbscript:, data:text/html)",
        _rx(r"\b(?:javascript|vbscript)\s*:|\bdata\s*:\s*text/html"),
    ),
    Rule(
        "XSS-004",
        EventCategory.XSS,
        Severity.MEDIUM,
        "Embedding tag (iframe, object, embed, base)",
        _rx(r"<\s*(?:iframe|object|embed|base|meta)\b"),
    ),
    # --- Path traversal -----------------------------------------------------------------------
    Rule(
        "TRAV-001",
        EventCategory.PATH_TRAVERSAL,
        Severity.MEDIUM,
        "Directory traversal sequence (../)",
        _rx(r"(?:^|[/\\=])\.\.[/\\]"),
    ),
    Rule(
        "TRAV-002",
        EventCategory.PATH_TRAVERSAL,
        Severity.HIGH,
        "Sensitive system file (/etc/passwd, win.ini, /proc/self)",
        _rx(r"/etc/(?:passwd|shadow|hosts)\b|\bwin\.ini\b|\bboot\.ini\b|/proc/self/"),
    ),
    # --- Command injection --------------------------------------------------------------------
    Rule(
        "CMDI-001",
        EventCategory.COMMAND_INJECTION,
        Severity.HIGH,
        "Shell command chained with ; & | or $( )",
        _rx(
            r"(?:[;&|`]|\$\()\s*(?:cat|ls|id|whoami|uname|curl|wget|nc|ncat|bash|sh|zsh|"
            r"powershell|cmd(?:\.exe)?|ping|nslookup|python[23]?|perl|php|rm)\b"
        ),
    ),
    # --- Server-side request forgery ----------------------------------------------------------
    Rule(
        "SSRF-001",
        EventCategory.SSRF,
        Severity.HIGH,
        "Cloud metadata service address",
        _rx(r"169\.254\.169\.254|metadata\.google\.internal|\bfd00:ec2::254\b|100\.100\.100\.200"),
        locations=FETCHABLE,
    ),
    Rule(
        "SSRF-002",
        EventCategory.SSRF,
        Severity.HIGH,
        "URL pointing at an internal address or a non-HTTP scheme",
        _rx(
            r"\b(?:https?|gopher|dict|ftp|ldap)://(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|"
            r"\[?::1\]?|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)"
            r"|\b(?:file|gopher|dict)://"
        ),
        locations=FETCHABLE,
    ),
    # --- Tools and reconnaissance -------------------------------------------------------------
    Rule(
        "SCAN-001",
        EventCategory.SCANNER,
        Severity.LOW,
        "Known attack or scanning tool in the User-Agent",
        _rx(
            r"\b(?:sqlmap|nikto|nuclei|masscan|zgrab|wpscan|dirbuster|gobuster|ffuf|feroxbuster|"
            r"acunetix|nessus|openvas|w3af|arachni|jaeles)\b"
        ),
        locations=(Location.USER_AGENT,),
    ),
    Rule(
        "RECON-001",
        EventCategory.RECON,
        Severity.LOW,
        "Request for a well-known sensitive file or admin path",
        _rx(
            r"/(?:\.env\b|\.git/|\.aws/|\.ssh/|wp-admin|wp-login\.php|phpmyadmin|server-status|"
            r"actuator\b|\.ds_store|config\.(?:php|json|ya?ml)|backup\.(?:zip|sql|tar))"
        ),
        locations=(Location.PATH,),
        unmatched_routes_only=True,
    ),
)

INJECTION_CATEGORIES = frozenset(
    {
        EventCategory.SQL_INJECTION,
        EventCategory.COMMAND_INJECTION,
        EventCategory.PATH_TRAVERSAL,
        EventCategory.SSRF,
        EventCategory.XSS,
    }
)


@dataclass(frozen=True)
class InspectedRequest:
    method: str
    path: str
    query_string: str = ""
    user_agent: str | None = None
    referer: str | None = None
    content_type: str | None = None
    body: bytes = b""
    route_matched: bool = True
    # Top-level JSON fields not inspected for this endpoint (documented exclusions).
    excluded_fields: frozenset[str] = frozenset()


@dataclass(frozen=True)
class Finding:
    rule_id: str
    category: EventCategory
    severity: Severity
    description: str
    location: str  # path | query | body | user_agent | referer
    field: str | None  # query parameter or JSON field, when there is one
    snippet: str


@dataclass(frozen=True)
class Analysis:
    findings: tuple[Finding, ...] = field(default_factory=tuple)

    @property
    def severity(self) -> Severity:
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    @property
    def category(self) -> EventCategory:
        """The category of the most severe finding (first in rule order on a tie)."""
        top = self.severity
        return next(f.category for f in self.findings if f.severity is top)

    def __bool__(self) -> bool:
        return bool(self.findings)


def normalize(value: str) -> str:
    """Percent-decode up to twice (catching double encoding), drop NULs, unify slashes."""
    decoded = value
    for _ in range(2):
        once = unquote_plus(decoded)
        if once == decoded:
            break
        decoded = once
    return decoded.replace("\x00", "")


def _clean(text: str) -> str:
    return _CONTROL.sub("?", text)[:SNIPPET_MAX]


def _snippet(value: str, start: int, end: int) -> str:
    lo, hi = max(0, start - SNIPPET_CONTEXT), min(len(value), end + SNIPPET_CONTEXT)
    prefix = "…" if lo else ""
    suffix = "…" if hi < len(value) else ""
    return _clean(f"{prefix}{value[lo:hi]}{suffix}")


def _json_fields(data: object, prefix: str = "") -> Iterator[tuple[str, str]]:
    """Every string leaf (and object key) with a dotted field path; bounded by MAX_BODY."""
    if isinstance(data, dict):
        for key, value in data.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            yield name, str(key)
            yield from _json_fields(value, name)
    elif isinstance(data, list):
        for index, item in enumerate(data[:200]):
            yield from _json_fields(item, f"{prefix}[{index}]")
    elif isinstance(data, str):
        yield prefix, data
    elif data is not None and not isinstance(data, bool):
        yield prefix, str(data)


def _targets(request: InspectedRequest) -> Iterator[tuple[str, str | None, str, bool]]:
    """(location, field, decoded value, sensitive) for everything the attacker controls."""
    yield Location.PATH, None, normalize(request.path[:MAX_PATH]), False
    for name, value in parse_qsl(request.query_string[:MAX_QUERY], keep_blank_values=True):
        sensitive = bool(_SENSITIVE_FIELD.search(name))
        yield Location.QUERY, name, normalize(name), False
        yield Location.QUERY, name, normalize(value), sensitive
    if request.user_agent:
        yield Location.USER_AGENT, None, request.user_agent[:MAX_HEADER], False
    if request.referer:
        yield Location.REFERER, None, normalize(request.referer[:MAX_HEADER]), False
    if request.body:
        yield from _body_targets(request)


def _body_targets(request: InspectedRequest) -> Iterator[tuple[str, str | None, str, bool]]:
    raw = request.body[:MAX_BODY].decode("utf-8", errors="replace")
    if "json" in (request.content_type or "").lower():
        try:
            data = json.loads(raw)
        except ValueError:
            data = None
        if data is not None:
            for name, value in _json_fields(data):
                top = name.split(".", 1)[0].split("[", 1)[0]
                if top in request.excluded_fields:
                    continue
                sensitive = bool(_SENSITIVE_FIELD.search(name.rsplit(".", 1)[-1]))
                yield Location.BODY, name, normalize(value), sensitive
            return
    yield Location.BODY, None, normalize(raw), False


def analyze(request: InspectedRequest) -> Analysis:
    """Every rule that matches, at most once per rule (its first location)."""
    findings: list[Finding] = []
    seen: set[str] = set()
    targets = list(_targets(request))
    for rule in RULES:
        if rule.unmatched_routes_only and request.route_matched:
            continue
        for location, field_name, value, sensitive in targets:
            if location not in rule.locations or rule.rule_id in seen:
                continue
            match = rule.pattern.search(value)
            if match is None:
                continue
            seen.add(rule.rule_id)
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    category=rule.category,
                    severity=rule.severity,
                    description=rule.description,
                    location=location,
                    field=_clean(field_name) if field_name else None,
                    snippet=REDACTED if sensitive else _snippet(value, match.start(), match.end()),
                )
            )
    return Analysis(tuple(findings))


def event_severity(analysis: Analysis, status_code: int) -> Severity:
    """An injection payload that got a success response deserves more attention than one the
    application rejected: raise it one level."""
    severity = analysis.severity
    if status_code < 400 and any(f.category in INJECTION_CATEGORIES for f in analysis.findings):
        return severity.raised()
    return severity
