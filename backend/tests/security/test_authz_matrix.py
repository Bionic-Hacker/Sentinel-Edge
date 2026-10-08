"""Function-level authorization (OWASP API5 BFLA, spec §28): the route table *is* the policy.

1. Every route declares exactly one access class, and the complete table must equal EXPECTED,
   written independently below. Adding a route without adding it here fails CI.
2. A sweep calls every protected route as every role, plus anonymously, and checks the outcome
   matches the table: the policy is enforced, not just declared.
"""

from __future__ import annotations

import re
import uuid
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.routing import APIRoute, iter_route_contexts
from fastapi.testclient import TestClient

from app.core.authz import authenticated_setup, public_endpoint
from app.models.user import ROLES_REQUIRING_MFA, Role
from tests.conftest import make_settings
from tests.helpers import bearer, create_user, session_token

pytestmark = pytest.mark.security

PUBLIC = "public"
SETUP = "setup"  # any signed-in user, even with setup pending (finish-setup flows)
ALL = frozenset(Role)
ADMIN = frozenset({Role.ADMIN})
AUDITORS = frozenset({Role.ADMIN, Role.SECURITY_ENGINEER})
API_SECURITY = frozenset({Role.ADMIN, Role.SECURITY_ENGINEER, Role.DEVELOPER})
SECOPS_READ = frozenset({Role.ADMIN, Role.SECURITY_ENGINEER, Role.ANALYST, Role.VIEWER})
INVESTIGATORS = frozenset({Role.ADMIN, Role.SECURITY_ENGINEER, Role.ANALYST})
REMEDIATORS = frozenset({Role.ADMIN, Role.SECURITY_ENGINEER, Role.DEVELOPER})
LEADS = frozenset({Role.ADMIN, Role.SECURITY_ENGINEER})

EXPECTED: dict[tuple[str, str], str | frozenset[Role]] = {
    ("GET", "/api/v1/health"): PUBLIC,
    ("GET", "/api/v1/ready"): PUBLIC,
    ("POST", "/api/v1/auth/login"): PUBLIC,
    ("POST", "/api/v1/auth/mfa/verify"): PUBLIC,
    ("POST", "/api/v1/auth/refresh"): PUBLIC,
    ("POST", "/api/v1/auth/password/forgot"): PUBLIC,
    ("POST", "/api/v1/auth/password/reset"): PUBLIC,
    ("POST", "/api/v1/auth/logout"): SETUP,
    ("GET", "/api/v1/auth/me"): SETUP,
    ("POST", "/api/v1/auth/mfa/enroll"): SETUP,
    ("POST", "/api/v1/auth/mfa/enroll/confirm"): SETUP,
    ("POST", "/api/v1/auth/password/change"): SETUP,
    ("GET", "/api/v1/platform/capabilities"): ALL,
    ("GET", "/api/v1/users"): ADMIN,
    ("POST", "/api/v1/users"): ADMIN,
    ("GET", "/api/v1/users/{user_id}"): ALL,  # plus an object-level check (own record only)
    ("PATCH", "/api/v1/users/{user_id}"): ADMIN,
    ("POST", "/api/v1/users/{user_id}/mfa/reset"): ADMIN,
    ("DELETE", "/api/v1/users/{user_id}"): ADMIN,
    ("GET", "/api/v1/audit-logs"): AUDITORS,
    ("GET", "/api/v1/audit-logs/verify"): AUDITORS,
    ("GET", "/api/v1/api-security/inventory"): API_SECURITY,
    ("GET", "/api/v1/api-security/owasp"): API_SECURITY,
    ("GET", "/api/v1/security-events"): SECOPS_READ,
    ("GET", "/api/v1/security-events/{event_id}"): SECOPS_READ,
    ("GET", "/api/v1/incidents"): SECOPS_READ,
    ("POST", "/api/v1/incidents"): INVESTIGATORS,
    ("GET", "/api/v1/incidents/assignees"): INVESTIGATORS,
    ("GET", "/api/v1/incidents/{incident_id}"): SECOPS_READ,
    # Plus object-level rules: analysts change only incidents assigned to them, and closing,
    # reopening, re-rating and assigning others are lead-only (test_incidents.py).
    ("PATCH", "/api/v1/incidents/{incident_id}"): INVESTIGATORS,
    ("POST", "/api/v1/incidents/{incident_id}/transitions"): INVESTIGATORS,
    ("POST", "/api/v1/incidents/{incident_id}/assignment"): INVESTIGATORS,
    ("POST", "/api/v1/incidents/{incident_id}/notes"): INVESTIGATORS,
    ("POST", "/api/v1/incidents/{incident_id}/events"): INVESTIGATORS,
    ("GET", "/api/v1/security/overview"): SECOPS_READ,
    ("GET", "/api/v1/applications"): ALL,  # plus an object-level filter (developers: own apps)
    ("POST", "/api/v1/applications"): AUDITORS,
    ("GET", "/api/v1/applications/owners"): AUDITORS,
    ("GET", "/api/v1/applications/{application_id}"): ALL,  # plus an object-level check
    ("PATCH", "/api/v1/applications/{application_id}"): AUDITORS,
    ("GET", "/api/v1/simulator/scenarios"): INVESTIGATORS,
    ("GET", "/api/v1/simulator/runs"): INVESTIGATORS,
    ("POST", "/api/v1/simulator/runs"): AUDITORS,
    ("GET", "/api/v1/simulator/waf-rules"): INVESTIGATORS,
    ("PUT", "/api/v1/simulator/waf-rules/{rule_id}"): AUDITORS,
    # Vulnerability management (Phase 8): every role reads, developers their own applications.
    ("GET", "/api/v1/vulnerabilities"): ALL,  # plus an object-level filter
    ("GET", "/api/v1/vulnerabilities/overview"): ALL,  # plus an object-level filter
    ("GET", "/api/v1/vulnerabilities/{vulnerability_id}"): ALL,  # plus an object-level check
    ("POST", "/api/v1/vulnerabilities/{vulnerability_id}/status"): REMEDIATORS,
    ("POST", "/api/v1/vulnerabilities/{vulnerability_id}/acceptances"): AUDITORS,
    (
        "POST",
        "/api/v1/vulnerabilities/{vulnerability_id}/acceptances/{acceptance_id}/revoke",
    ): AUDITORS,
    ("GET", "/api/v1/scans"): ALL,  # plus an object-level filter
    ("GET", "/api/v1/scans/{scan_id}"): ALL,  # plus an object-level check
    ("GET", "/api/v1/sboms"): ALL,  # plus an object-level filter
    ("GET", "/api/v1/sboms/{sbom_id}"): ALL,  # plus an object-level check
    ("GET", "/api/v1/sboms/{sbom_id}/document"): ALL,  # plus an object-level check
    ("GET", "/api/v1/governance/controls"): ALL,
    ("GET", "/api/v1/governance/requirements"): ALL,
    ("GET", "/api/v1/threat-models"): ALL,  # developers: own applications only
    ("POST", "/api/v1/threat-models"): LEADS,
    ("GET", "/api/v1/threat-models/{model_id}"): ALL,  # plus an object-level check
    ("PATCH", "/api/v1/threat-models/{model_id}"): LEADS,
    ("POST", "/api/v1/threat-models/{model_id}/elements"): LEADS,
    ("PATCH", "/api/v1/threat-models/{model_id}/elements/{element_id}"): LEADS,
    ("POST", "/api/v1/threat-models/{model_id}/threats"): LEADS,
    ("PATCH", "/api/v1/threat-models/{model_id}/threats/{threat_id}"): LEADS,
}


def _calls(dependant: Any) -> list[Any]:
    found = []
    for dep in dependant.dependencies:
        found.append(dep.call)
        found.extend(_calls(dep))
    return found


def _access_class(route: APIRoute) -> str | frozenset[Role]:
    calls = _calls(route.dependant)
    role_guards = [c for c in calls if hasattr(c, "allowed_roles")]
    is_public = public_endpoint in calls
    if is_public and (role_guards or authenticated_setup in calls):
        return "CONFLICT: public and authenticated"
    if is_public:
        return PUBLIC
    if len(role_guards) > 1:
        return "CONFLICT: several role guards"
    if role_guards:
        roles: frozenset[Role] = role_guards[0].allowed_roles
        return roles
    if authenticated_setup in calls:
        return SETUP
    return "UNDECLARED"


def _route_table(app: FastAPI) -> dict[tuple[str, str], str | frozenset[Role]]:
    """Every effective route with its full path (FastAPI keeps included routers nested, so
    walk them through iter_route_contexts rather than app.routes)."""
    table = {}
    for ctx in iter_route_contexts(app.routes):
        route = ctx.route
        if isinstance(route, APIRoute) and ctx.path.startswith("/api/"):
            for method in ctx.methods or ():
                table[(method, ctx.path)] = _access_class(route)
    return table


def test_every_route_declares_exactly_its_expected_access(app: FastAPI) -> None:
    actual = _route_table(app)
    undeclared = {
        k: v for k, v in actual.items() if isinstance(v, str) and v not in (PUBLIC, SETUP)
    }
    assert undeclared == {}, f"routes without a valid authorization declaration: {undeclared}"
    assert actual == EXPECTED


def test_table_is_not_empty(app: FastAPI) -> None:
    """Guard against the walker silently finding nothing (which would make the check vacuous)."""
    assert len(_route_table(app)) == len(EXPECTED)


# --- Enforcement sweep ----------------------------------------------------------------------


def _url(path: str) -> str:
    path = path.replace("{rule_id}", "XSS-999")  # a well-formed but unknown simulated rule
    return re.sub(r"\{\w+_id\}", lambda _: str(uuid.uuid4()), path)


@pytest.fixture
def tokens_by_role(db_app: FastAPI) -> dict[Role, str]:
    tokens = {}
    for role in Role:
        user = create_user(
            db_app,
            f"{role.value.lower()}@example.com",
            role=role,
            mfa_enabled=role in ROLES_REQUIRING_MFA,
            mfa_secret=b"x" if role in ROLES_REQUIRING_MFA else None,
        )
        tokens[role] = session_token(db_app, user, mfa_verified=role in ROLES_REQUIRING_MFA)
    return tokens


PROTECTED = [(m, p, a) for (m, p), a in EXPECTED.items() if a != PUBLIC]


@pytest.mark.db
@pytest.mark.parametrize(("method", "path", "access"), PROTECTED)
def test_anonymous_requests_are_rejected(
    db_client: TestClient, method: str, path: str, access: object
) -> None:
    response = db_client.request(method, _url(path), json={})
    assert response.status_code == 401, response.text


@pytest.mark.db
@pytest.mark.parametrize(("method", "path", "access"), [p for p in PROTECTED if p[2] != SETUP])
def test_each_role_gets_exactly_the_access_the_matrix_grants(
    db_client: TestClient,
    tokens_by_role: dict[Role, str],
    method: str,
    path: str,
    access: frozenset[Role],
) -> None:
    for role, token in tokens_by_role.items():
        response = db_client.request(method, _url(path), json={}, headers=bearer(token))
        if role in access:
            assert response.status_code not in (401, 403), (role, response.text)
        else:
            assert response.status_code == 403, (role, response.text)
            assert response.json()["error"]["code"] == "forbidden"


def test_matrix_covers_settings_independent_app() -> None:
    """The table is the same however the app is configured (no config-dependent routes)."""
    from app.main import create_app

    docs_on = create_app(make_settings(enable_api_docs=True))
    table = {k: v for k, v in _route_table(docs_on).items() if k[1].startswith("/api/v1")}
    assert table == EXPECTED
