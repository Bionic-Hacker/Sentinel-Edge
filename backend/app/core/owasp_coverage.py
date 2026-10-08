"""OWASP API Security Top 10 (2023) coverage, with evidence.

Each category states how SentinelEdge addresses it today, what remains planned, and which
automated tests prove the controls. tests/security/test_owasp_coverage.py fails if any cited
test stops existing, so the evidence cannot silently go stale.

Status values:
  mitigated     controls implemented and tested for every exposed endpoint
  partial       application controls in place; a planned layer completes them
  not_exposed   no endpoint has this exposure yet; a guard exists for when one does
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from app.core.api_policy import OwaspApi


class CoverageStatus(StrEnum):
    MITIGATED = "mitigated"
    PARTIAL = "partial"
    NOT_EXPOSED = "not_exposed"


@dataclass(frozen=True)
class Coverage:
    category: OwaspApi
    status: CoverageStatus
    controls: tuple[str, ...]
    evidence: tuple[str, ...]  # "path/to/test_file.py::test_name", relative to backend/
    planned: str | None = None


T_USERS = "tests/integration/test_users_and_audit_api.py"
T_AUTHZ = "tests/security/test_authz_matrix.py"
T_LOGIN = "tests/integration/test_auth_login.py"
T_SESS = "tests/integration/test_auth_sessions.py"
T_MFA = "tests/integration/test_auth_mfa.py"
T_RL = "tests/integration/test_rate_limiting.py"
T_SWEEP = "tests/security/test_api_protections.py"
T_APPS = "tests/integration/test_applications.py"
T_INC = "tests/integration/test_incidents.py"
T_EVENTS = "tests/integration/test_security_events.py"
T_COR = "tests/integration/test_correlation.py"

COVERAGE: tuple[Coverage, ...] = (
    Coverage(
        OwaspApi.API1,
        CoverageStatus.MITIGATED,
        (
            "Object-level checks in the service layer for every record addressed by ID",
            "Other users' records return the same 404 as missing ones (no ID probing)",
            "Every object-level denial is audited (authz.denied)",
            "Developers see only the applications they own; analysts change only their incidents",
            "Repeated object-level denials from one account raise a detection (COR-004)",
        ),
        (
            f"{T_USERS}::test_users_can_read_only_their_own_record",
            f"{T_USERS}::test_denials_record_the_full_endpoint_template",
            f"{T_APPS}::test_developers_see_only_their_own_applications",
            f"{T_INC}::test_analysts_cannot_work_someone_elses_incident",
        ),
    ),
    Coverage(
        OwaspApi.API2,
        CoverageStatus.MITIGATED,
        (
            "Argon2id passwords; TOTP MFA required for privileged roles",
            "15-minute access tokens checked against a live session on every request",
            "Rotating refresh tokens with reuse (theft) detection",
            "Account lockout; enumeration-resistant errors; per-IP sign-in rate limits",
            "Credential stuffing and sign-ins from a stuffing source are detected (COR-001, 007)",
        ),
        (
            f"{T_LOGIN}::test_account_locks_after_repeated_failures",
            f"{T_SESS}::test_reused_refresh_token_revokes_the_whole_session",
            f"{T_MFA}::test_totp_code_cannot_be_replayed",
            f"{T_RL}::test_login_is_limited_per_ip_with_retry_after",
            f"{T_COR}::test_sign_in_from_a_stuffing_source_is_detected",
        ),
    ),
    Coverage(
        OwaspApi.API3,
        CoverageStatus.MITIGATED,
        (
            "Responses are allow-listed by response models (no excessive data exposure)",
            "Request models reject unknown fields (no mass assignment)",
            "Sensitive fields (hashes, secrets, tokens) never appear in any response model",
        ),
        (
            f"{T_SWEEP}::test_every_request_body_rejects_unknown_fields",
            f"{T_SWEEP}::test_every_json_route_declares_a_response_model",
            f"{T_SWEEP}::test_no_response_model_exposes_secret_fields",
            f"{T_USERS}::test_user_records_expose_exactly_the_allowed_fields",
        ),
    ),
    Coverage(
        OwaspApi.API4,
        CoverageStatus.PARTIAL,
        (
            "Token-bucket rate limits on every endpoint, per IP and per account",
            "Page-size caps on list endpoints; 1 MB request body limit at the proxy",
            "15-second database statement timeout for the API role",
            "Security-event recording is throttled per source, so floods cannot fill the store",
        ),
        (
            f"{T_EVENTS}::test_recording_is_throttled_per_source_ip",
            f"{T_RL}::test_concurrent_requests_never_overspend_a_bucket",
            f"{T_RL}::test_user_limit_follows_the_account_across_ip_addresses",
            f"{T_USERS}::test_audit_query_parameters_validated",
        ),
        planned="AWS WAF rate-based rules absorb volume at the edge (Phase 5)",
    ),
    Coverage(
        OwaspApi.API5,
        CoverageStatus.MITIGATED,
        (
            "Every route declares its allowed roles; a test fails on any undeclared route",
            "A sweep calls every route as every role and anonymously",
            "Role and session are re-read from the database on every request",
        ),
        (
            f"{T_AUTHZ}::test_every_route_declares_exactly_its_expected_access",
            f"{T_USERS}::test_only_admins_can_delete_users",
            f"{T_INC}::test_viewers_read_but_never_write",
        ),
    ),
    Coverage(
        OwaspApi.API6,
        CoverageStatus.PARTIAL,
        (
            "Sign-in, MFA, password recovery and invitations are rate limited per IP or account",
            "Recovery never reveals whether an account exists",
            "Throttled sign-ins are rejected before any password check",
        ),
        (
            f"{T_RL}::test_throttled_logins_do_no_password_work",
            f"{T_RL}::test_a_flood_is_audited_once_not_per_request",
        ),
        planned="AWS WAF Bot Control and CAPTCHA challenges at the edge (Phase 5)",
    ),
    Coverage(
        OwaspApi.API7,
        CoverageStatus.NOT_EXPOSED,
        (
            "No endpoint fetches a caller-supplied URL",
            "Outbound guard ready: HTTPS only, host allow-list, every resolved address must be "
            "public (blocks 169.254.169.254, RFC 1918, loopback, IPv6 and mapped forms)",
        ),
        (
            "tests/unit/test_egress.py::test_internal_addresses_are_refused",
            "tests/unit/test_egress.py::test_one_internal_answer_is_enough_to_refuse",
        ),
        planned="Applied to every outbound call when AI integrations arrive (Phase 9)",
    ),
    Coverage(
        OwaspApi.API8,
        CoverageStatus.PARTIAL,
        (
            "Strict security headers and CSP on every response, including errors",
            "Host-header allow-list; generic errors with correlation IDs, no stack traces",
            "API docs disabled outside local; insecure settings refused when deployed",
            "Hardened containers: non-root, read-only, no capabilities",
        ),
        (
            "tests/security/test_security_headers.py::test_headers_on_normal_and_error_responses",
            "tests/security/test_trusted_host.py::test_unexpected_host_rejected",
            "tests/security/test_error_handling.py::test_unhandled_exception_returns_generic_envelope",
        ),
        planned="TLS 1.2+ policy and HSTS at CloudFront with ACM certificates (Phase 5)",
    ),
    Coverage(
        OwaspApi.API9,
        CoverageStatus.MITIGATED,
        (
            "The inventory is generated from the live route table",
            "Every route must have a policy entry, and no entry may outlive its route",
            "Requests to undocumented paths are counted as probing signals",
            "Single versioned prefix (/api/v1)",
        ),
        (
            "tests/security/test_api_inventory.py::test_registry_matches_the_route_table",
            "tests/security/test_api_inventory.py::test_unmatched_requests_are_counted",
        ),
    ),
    Coverage(
        OwaspApi.API10,
        CoverageStatus.NOT_EXPOSED,
        ("The API consumes no third-party API today",),
        ("tests/unit/test_egress.py::test_allow_list_is_enforced_before_resolution",),
        planned="Bedrock responses validated against a strict output contract (ADR-0007, Phase 9)",
    ),
)
