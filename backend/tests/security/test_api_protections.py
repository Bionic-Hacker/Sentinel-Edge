"""Route-table sweeps for OWASP API3 (object property level authorization).

They check every route, current and future, so a new endpoint cannot quietly accept extra
fields (mass assignment) or return an unlisted one (excessive data exposure).
"""

from __future__ import annotations

import re
import types
import typing
from collections.abc import Iterator
from typing import Any, get_args, get_origin

import pytest
from fastapi import FastAPI, Response
from fastapi.routing import APIRoute, iter_route_contexts
from pydantic import BaseModel

pytestmark = pytest.mark.security

SENSITIVE_NAME = re.compile(r"password|secret|token|hash|recovery", re.IGNORECASE)
# Fields that look sensitive but whose whole purpose is to hand the value to its owner, once.
APPROVED_SENSITIVE = {
    ("AuthenticatedResponse", "access_token"): "the result of signing in, in memory only",
    ("AuthenticatedResponse", "token_type"): "always 'bearer'",
    ("MfaRequiredResponse", "challenge_token"): "short-lived, single-purpose MFA challenge",
    ("MfaEnrollmentStartResponse", "secret"): "shown once so the user can enroll MFA",
    ("RecoveryCodesResponse", "recovery_codes"): "shown once at enrollment",
    ("UserOut", "must_change_password"): "a yes/no flag, not a password",
    ("AuditEntryOut", "prev_hash"): "public integrity value of the audit hash chain",
    ("AuditEntryOut", "record_hash"): "public integrity value of the audit hash chain",
    ("ChainStatus", "head_hash"): "public integrity value of the audit hash chain",
}
NEVER_RETURNED = {"password", "password_hash", "mfa_secret", "mfa_pending_secret", "token_hash"}


def _api_routes(app: FastAPI) -> Iterator[tuple[str, APIRoute]]:
    for ctx in iter_route_contexts(app.routes):
        if isinstance(ctx.route, APIRoute) and (ctx.path or "").startswith("/api/"):
            yield ctx.path or "", ctx.route


def _models(annotation: Any) -> Iterator[type[BaseModel]]:
    """Every pydantic model reachable from an annotation (unions, lists, nested fields)."""
    seen: set[type[BaseModel]] = set()
    stack = [annotation]
    while stack:
        current = stack.pop()
        if isinstance(current, type) and issubclass(current, BaseModel):
            if current in seen:
                continue
            seen.add(current)
            yield current
            stack.extend(field.annotation for field in current.model_fields.values())
        elif get_origin(current) in (typing.Union, types.UnionType, list, dict, tuple, set):
            stack.extend(get_args(current))


def test_every_request_body_rejects_unknown_fields(app: FastAPI) -> None:
    """Mass assignment: a client cannot set fields the endpoint did not ask for (e.g. "role"
    on an invite, "is_active" on create, "password_hash" anywhere)."""
    checked = 0
    for path, route in _api_routes(app):
        for param in route.dependant.body_params:
            for model in _models(param.field_info.annotation):
                assert model.model_config.get("extra") == "forbid", f"{path}: {model.__name__}"
                checked += 1
    assert checked >= 8  # guard against the sweep silently finding nothing


# Routes that return a file instead of JSON: each one is reviewed and listed here.
FILE_DOWNLOADS = frozenset({("GET", "/api/v1/sboms/{sbom_id}/document")})


def test_every_json_route_declares_a_response_model(app: FastAPI) -> None:
    """Excessive data exposure: responses are allow-listed by a model, never a raw object."""
    downloads = set()
    for path, route in _api_routes(app):
        if route.status_code == 204:
            continue
        if route.response_model is None and route.response_class is Response:
            downloads.update((method, path) for method in route.methods)
            continue
        assert route.response_model is not None, f"{sorted(route.methods)} {path}"
    assert downloads == FILE_DOWNLOADS


def test_no_response_model_exposes_secret_fields(app: FastAPI) -> None:
    unexpected = []
    for path, route in _api_routes(app):
        for model in _models(route.response_model):
            for name in model.model_fields:
                assert name not in NEVER_RETURNED, f"{path}: {model.__name__}.{name}"
                if SENSITIVE_NAME.search(name) and (model.__name__, name) not in APPROVED_SENSITIVE:
                    unexpected.append(f"{path}: {model.__name__}.{name}")
    assert unexpected == [], "new sensitive-looking response fields need explicit approval"


def test_inspection_exclusions_name_real_routes_and_fields(app: FastAPI) -> None:
    """HTTP analysis skips a few free-text fields where analysts quote attack strings. Each
    exclusion must name an existing route and a field of its request body: a renamed field or
    route must not silently widen or orphan an exclusion."""
    from app.core.http_inspection import INSPECTION_EXCLUSIONS

    bodies: dict[tuple[str, str], set[str]] = {}
    for path, route in _api_routes(app):
        body = route.body_field
        if body is not None and isinstance(body.field_info.annotation, type):
            model = body.field_info.annotation
            if issubclass(model, BaseModel):
                for method in route.methods:
                    bodies[(method, path)] = set(model.model_fields)
    assert INSPECTION_EXCLUSIONS
    for key, fields in INSPECTION_EXCLUSIONS.items():
        assert key in bodies, f"exclusion for unknown route {key}"
        assert fields <= bodies[key], f"{key}: {sorted(fields - bodies[key])} not in the body"
