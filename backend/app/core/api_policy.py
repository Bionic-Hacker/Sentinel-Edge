"""Endpoint security policy: one registry for risk, rate limits and OWASP API exposure.

Every API route must appear here exactly once, and nothing else may. A test compares this
registry with the live route table (OWASP API9, improper inventory management): an endpoint
cannot ship without a risk rating and a rate limit, and a removed endpoint cannot linger in the
inventory. The rate limiter and the API inventory both read this table, so what the inventory
reports is what the code enforces.

Authentication and authorization are NOT declared here; they are read from each route's own
dependencies (app.core.authz), the code that actually enforces them.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from fastapi import FastAPI, Request
from fastapi.routing import APIRoute, iter_route_contexts


class OwaspApi(StrEnum):
    """OWASP API Security Top 10, 2023 edition."""

    API1 = "API1:2023 Broken Object Level Authorization"
    API2 = "API2:2023 Broken Authentication"
    API3 = "API3:2023 Broken Object Property Level Authorization"
    API4 = "API4:2023 Unrestricted Resource Consumption"
    API5 = "API5:2023 Broken Function Level Authorization"
    API6 = "API6:2023 Unrestricted Access to Sensitive Business Flows"
    API7 = "API7:2023 Server Side Request Forgery"
    API8 = "API8:2023 Security Misconfiguration"
    API9 = "API9:2023 Improper Inventory Management"
    API10 = "API10:2023 Unsafe Consumption of APIs"

    @property
    def code(self) -> str:
        return self.value.split(":", 1)[0]


class Risk(StrEnum):
    """Inherent risk if the endpoint's controls failed: impact on credentials, privileges and
    evidence, and exposure (public versus signed-in)."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class LimitScope(StrEnum):
    IP = "ip"  # keyed by client IP; applied before authentication
    USER = "user"  # keyed by account; applied after authentication


@dataclass(frozen=True)
class RateLimitPolicy:
    """Token bucket: `capacity` requests in a burst, refilling at `capacity` per `period_s`."""

    name: str
    capacity: int
    period_s: int
    scope: LimitScope

    @property
    def refill_per_second(self) -> float:
        return self.capacity / self.period_s

    @property
    def description(self) -> str:
        """Compact form for tables and audit records, e.g. "20 / 2 min per IP"."""
        scope = "IP" if self.scope is LimitScope.IP else "user"
        minutes, seconds = divmod(self.period_s, 60)
        if seconds:
            return f"{self.capacity} / {self.period_s} s per {scope}"
        window = "min" if minutes == 1 else f"{minutes} min"
        return f"{self.capacity} / {window} per {scope}"


# --- Policies ------------------------------------------------------------------------------
# Login allows a burst of 20 per IP, then one attempt every 6 seconds; account lockout after 5
# failures still applies per account. WAF rate-based rules add a volume limit at the edge
# (Phase 5).
GLOBAL_IP = RateLimitPolicy("ip_global", 600, 60, LimitScope.IP)
PROBE = RateLimitPolicy("probe", 120, 60, LimitScope.IP)
LOGIN = RateLimitPolicy("login", 20, 120, LimitScope.IP)
MFA_VERIFY = RateLimitPolicy("mfa_verify", 20, 120, LimitScope.IP)
TOKEN_REFRESH = RateLimitPolicy("token_refresh", 30, 60, LimitScope.IP)
ACCOUNT_RECOVERY = RateLimitPolicy("account_recovery", 5, 900, LimitScope.IP)
SESSION = RateLimitPolicy("session", 60, 60, LimitScope.USER)
CREDENTIAL_CHANGE = RateLimitPolicy("credential_change", 10, 300, LimitScope.USER)
READ = RateLimitPolicy("read", 120, 60, LimitScope.USER)
ADMIN_WRITE = RateLimitPolicy("admin_write", 30, 60, LimitScope.USER)
EXPENSIVE = RateLimitPolicy("expensive", 6, 60, LimitScope.USER)
# Incident work: notes, transitions, assignment and evidence links by an investigator.
INVESTIGATION = RateLimitPolicy("investigation", 60, 60, LimitScope.USER)
# Not an endpoint policy: bounds how many attack-detection events one source IP can create, so a
# flood of malicious requests cannot flood the event store (app.core.http_inspection).
DETECTION_EVENTS = RateLimitPolicy("detection_events", 30, 60, LimitScope.IP)

ALL_POLICIES: tuple[RateLimitPolicy, ...] = (
    GLOBAL_IP,
    PROBE,
    LOGIN,
    MFA_VERIFY,
    TOKEN_REFRESH,
    ACCOUNT_RECOVERY,
    SESSION,
    CREDENTIAL_CHANGE,
    READ,
    ADMIN_WRITE,
    EXPENSIVE,
    INVESTIGATION,
    DETECTION_EVENTS,
)


@dataclass(frozen=True)
class EndpointPolicy:
    summary: str
    risk: Risk
    rate_limit: RateLimitPolicy
    owasp: tuple[OwaspApi, ...]  # the categories this endpoint is most exposed to
    data: str  # the most sensitive data the endpoint handles
    # Object-level rule enforced in the service layer, beyond the route's role guard.
    object_rule: str | None = None


A = OwaspApi
ENDPOINTS: dict[tuple[str, str], EndpointPolicy] = {
    ("GET", "/api/v1/health"): EndpointPolicy(
        "Liveness probe", Risk.LOW, PROBE, (A.API8,), "Version string"
    ),
    ("GET", "/api/v1/ready"): EndpointPolicy(
        "Readiness probe (database reachable)", Risk.LOW, PROBE, (A.API4, A.API8), "None"
    ),
    ("POST", "/api/v1/auth/login"): EndpointPolicy(
        "Password sign-in",
        Risk.CRITICAL,
        LOGIN,
        (A.API2, A.API4, A.API6),
        "Credentials",
    ),
    ("POST", "/api/v1/auth/mfa/verify"): EndpointPolicy(
        "Second-factor verification", Risk.CRITICAL, MFA_VERIFY, (A.API2, A.API4), "TOTP codes"
    ),
    ("POST", "/api/v1/auth/refresh"): EndpointPolicy(
        "Rotate refresh token, issue access token",
        Risk.HIGH,
        TOKEN_REFRESH,
        (A.API2,),
        "Session tokens",
    ),
    ("POST", "/api/v1/auth/password/forgot"): EndpointPolicy(
        "Request a password-reset link",
        Risk.HIGH,
        ACCOUNT_RECOVERY,
        (A.API2, A.API4, A.API6),
        "Email address",
    ),
    ("POST", "/api/v1/auth/password/reset"): EndpointPolicy(
        "Set a password from a reset or invite link",
        Risk.CRITICAL,
        ACCOUNT_RECOVERY,
        (A.API2, A.API6),
        "Credentials, one-time tokens",
    ),
    ("POST", "/api/v1/auth/logout"): EndpointPolicy(
        "End the current session", Risk.LOW, SESSION, (A.API2,), "Session tokens"
    ),
    ("GET", "/api/v1/auth/me"): EndpointPolicy(
        "Current user's profile", Risk.LOW, SESSION, (A.API3,), "Own profile (email, role)"
    ),
    ("POST", "/api/v1/auth/mfa/enroll"): EndpointPolicy(
        "Start TOTP enrollment", Risk.HIGH, CREDENTIAL_CHANGE, (A.API2,), "TOTP secret"
    ),
    ("POST", "/api/v1/auth/mfa/enroll/confirm"): EndpointPolicy(
        "Confirm TOTP enrollment, issue recovery codes",
        Risk.HIGH,
        CREDENTIAL_CHANGE,
        (A.API2, A.API4),
        "Recovery codes",
    ),
    ("POST", "/api/v1/auth/password/change"): EndpointPolicy(
        "Change own password", Risk.HIGH, CREDENTIAL_CHANGE, (A.API2,), "Credentials"
    ),
    ("GET", "/api/v1/platform/capabilities"): EndpointPolicy(
        "Capability register (what is real, local, simulated)",
        Risk.LOW,
        READ,
        (A.API9,),
        "Platform metadata",
    ),
    ("GET", "/api/v1/users"): EndpointPolicy(
        "List users", Risk.MEDIUM, READ, (A.API3, A.API5), "User directory (PII: email)"
    ),
    ("POST", "/api/v1/users"): EndpointPolicy(
        "Invite a user", Risk.HIGH, ADMIN_WRITE, (A.API3, A.API5, A.API6), "PII, role grants"
    ),
    ("GET", "/api/v1/users/{user_id}"): EndpointPolicy(
        "Read one user (own record unless admin)",
        Risk.MEDIUM,
        READ,
        (A.API1, A.API3),
        "PII (email)",
        object_rule="Own record only, unless ADMIN; others' IDs return 404",
    ),
    ("PATCH", "/api/v1/users/{user_id}"): EndpointPolicy(
        "Change a user's role or status",
        Risk.CRITICAL,
        ADMIN_WRITE,
        (A.API1, A.API3, A.API5),
        "Role grants",
        object_rule="Cannot demote or deactivate yourself or the last active admin",
    ),
    ("POST", "/api/v1/users/{user_id}/mfa/reset"): EndpointPolicy(
        "Reset a user's MFA",
        Risk.CRITICAL,
        ADMIN_WRITE,
        (A.API1, A.API5),
        "MFA state",
        object_rule="Cannot reset your own MFA (use a recovery code)",
    ),
    ("DELETE", "/api/v1/users/{user_id}"): EndpointPolicy(
        "Permanently delete a user",
        Risk.CRITICAL,
        ADMIN_WRITE,
        (A.API1, A.API5),
        "Account and credentials",
        object_rule="Cannot delete yourself or the last active admin",
    ),
    ("GET", "/api/v1/audit-logs"): EndpointPolicy(
        "Query the audit log", Risk.MEDIUM, READ, (A.API3, A.API5), "Security evidence, PII"
    ),
    ("GET", "/api/v1/api-security/inventory"): EndpointPolicy(
        "API inventory with controls and 24-hour metrics",
        Risk.MEDIUM,
        READ,
        (A.API5, A.API9),
        "Attack-surface map",
    ),
    ("GET", "/api/v1/api-security/owasp"): EndpointPolicy(
        "OWASP API Top 10 coverage", Risk.LOW, READ, (A.API5, A.API9), "Control evidence"
    ),
    ("GET", "/api/v1/security-events"): EndpointPolicy(
        "Query security events",
        Risk.MEDIUM,
        READ,
        (A.API3, A.API5),
        "Security telemetry: source IPs, attack payload snippets",
    ),
    ("GET", "/api/v1/security-events/{event_id}"): EndpointPolicy(
        "Read one security event with its evidence",
        Risk.MEDIUM,
        READ,
        (A.API3, A.API5),
        "Security evidence (bounded, redacted)",
    ),
    ("GET", "/api/v1/incidents"): EndpointPolicy(
        "List incidents",
        Risk.MEDIUM,
        READ,
        (A.API3, A.API5),
        "Incident records: source IPs, account names",
    ),
    ("POST", "/api/v1/incidents"): EndpointPolicy(
        "Open an incident from events",
        Risk.MEDIUM,
        INVESTIGATION,
        (A.API3, A.API5, A.API6),
        "Incident records, evidence links",
        object_rule="Evidence must share one provenance and not belong to another incident",
    ),
    ("GET", "/api/v1/incidents/assignees"): EndpointPolicy(
        "People an incident can be assigned to",
        Risk.LOW,
        READ,
        (A.API3, A.API5),
        "Names and roles of investigators",
    ),
    ("GET", "/api/v1/incidents/{incident_id}"): EndpointPolicy(
        "Read an incident with timeline, evidence and integrity check",
        Risk.MEDIUM,
        READ,
        (A.API3, A.API5),
        "Security evidence, analyst notes",
    ),
    ("PATCH", "/api/v1/incidents/{incident_id}"): EndpointPolicy(
        "Edit an incident's title, summary, remediation or severity",
        Risk.HIGH,
        INVESTIGATION,
        (A.API1, A.API3, A.API5),
        "Incident records",
        object_rule="Analysts edit only incidents assigned to them; severity is lead-only",
    ),
    ("POST", "/api/v1/incidents/{incident_id}/transitions"): EndpointPolicy(
        "Move an incident through the workflow",
        Risk.HIGH,
        INVESTIGATION,
        (A.API1, A.API5, A.API6),
        "Incident state",
        object_rule="Analysts move only their own incidents; closing and reopening are lead-only",
    ),
    ("POST", "/api/v1/incidents/{incident_id}/assignment"): EndpointPolicy(
        "Assign or take an incident",
        Risk.MEDIUM,
        INVESTIGATION,
        (A.API1, A.API5),
        "Incident ownership",
        object_rule="Analysts may only take an unassigned incident; leads assign anyone",
    ),
    ("POST", "/api/v1/incidents/{incident_id}/notes"): EndpointPolicy(
        "Add an analyst note to the timeline",
        Risk.LOW,
        INVESTIGATION,
        (A.API3, A.API4),
        "Analyst notes (append-only)",
    ),
    ("POST", "/api/v1/incidents/{incident_id}/events"): EndpointPolicy(
        "Attach security events as evidence",
        Risk.MEDIUM,
        INVESTIGATION,
        (A.API1, A.API3),
        "Evidence links (write-once)",
        object_rule="Own incidents only (analysts); one provenance; an event joins one incident",
    ),
    ("GET", "/api/v1/audit-logs/verify"): EndpointPolicy(
        "Verify the audit hash chain",
        Risk.MEDIUM,
        EXPENSIVE,
        (A.API4, A.API5),
        "Security evidence",
    ),
}


# --- Route templates -------------------------------------------------------------------------


def build_route_templates(app: FastAPI) -> dict[int, str]:
    """Map each route object to its full path template.

    FastAPI keeps included routers nested, so at request time `scope["route"].path` holds only
    the path relative to its router ("/users/{user_id}"). Endpoint policy, metrics and audit
    records need the full template ("/api/v1/users/{user_id}"), computed once here.
    """
    return {
        id(ctx.route): ctx.path
        for ctx in iter_route_contexts(app.routes)
        if isinstance(ctx.route, APIRoute) and ctx.path is not None
    }


def route_template(request: Request) -> str | None:
    """Full path template of the matched route, or None if no route matched."""
    route = request.scope.get("route")
    templates: dict[int, str] = getattr(request.app.state, "route_templates", {})
    return templates.get(id(route)) if route is not None else None


def endpoint_policy(request: Request) -> EndpointPolicy | None:
    template = route_template(request)
    return ENDPOINTS.get((request.method, template)) if template else None
