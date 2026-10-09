"""Capability register — the single source of truth for what SentinelEdge really does.

This is a machine-readable version of docs/feature-classification.md. It drives the UI's
"what is real" view and is guarded by tests (tests/unit/test_capabilities.py):

* nothing may be marked IMPLEMENTED with provenance REAL_AWS until a Terraform-managed
  resource and an integration test exist for it;
* every PLANNED entry must name the phase that delivers it.

Phase 1 contains no AWS integrations, so no entry is an implemented REAL_AWS capability.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from app.core.provenance import Provenance, Status


class Capability(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    key: str = Field(pattern=r"^[a-z0-9_.]+$")
    name: str
    area: str
    provenance: Provenance
    status: Status
    phase: int = Field(ge=1, le=12)
    note: str


def _c(
    key: str, name: str, area: str, prov: Provenance, status: Status, phase: int, note: str
) -> Capability:
    return Capability(
        key=key, name=name, area=area, provenance=prov, status=status, phase=phase, note=note
    )


L, S, R, D = Provenance.LOCAL, Provenance.SIMULATED, Provenance.REAL_AWS, Provenance.DEMO
DONE, PLAN = Status.IMPLEMENTED, Status.PLANNED

CAPABILITIES: tuple[Capability, ...] = (
    # --- Phase 1: implemented locally ---------------------------------------------------
    _c(
        "platform.health",
        "Health endpoint",
        "Platform",
        L,
        DONE,
        1,
        "GET /api/v1/health served by the local FastAPI container.",
    ),
    _c(
        "platform.security_headers",
        "API security headers",
        "Edge Security",
        L,
        DONE,
        1,
        "Applied by API middleware. CloudFront header policy follows in Phase 5.",
    ),
    _c(
        "platform.error_handling",
        "Secure error responses",
        "Platform",
        L,
        DONE,
        1,
        "Generic envelopes with correlation IDs; no stack traces or input echo.",
    ),
    _c(
        "platform.structured_logging",
        "Structured JSON logging with redaction",
        "Observability",
        L,
        DONE,
        1,
        "Written to stdout locally; shipped to CloudWatch Logs in Phase 4.",
    ),
    _c(
        "platform.trusted_hosts",
        "Host header allow-list",
        "API Security",
        L,
        DONE,
        1,
        "Rejects requests for unexpected Host headers.",
    ),
    _c(
        "devsecops.precommit",
        "Pre-commit secret scanning and linting",
        "DevSecOps",
        L,
        DONE,
        1,
        "Gitleaks, Ruff, Bandit locally and in the CI skeleton.",
    ),
    # --- Phase 2: implemented locally ---------------------------------------------------
    _c(
        "identity.auth",
        "Authentication, MFA, lockout",
        "Identity",
        L,
        DONE,
        2,
        "Argon2id, 15-minute JWT, rotating refresh tokens with reuse detection, TOTP MFA.",
    ),
    _c(
        "identity.rbac",
        "Role-based access control",
        "Identity",
        L,
        DONE,
        2,
        "Five roles; every route declares its access, verified by an automated sweep.",
    ),
    _c(
        "identity.user_admin",
        "User administration and invitations",
        "Identity",
        L,
        DONE,
        2,
        "Admins invite users by one-time link; they never see or set passwords.",
    ),
    _c(
        "audit.log",
        "Tamper-evident audit log",
        "Governance",
        L,
        DONE,
        2,
        "Hash-chained, append-only by grant and trigger. S3 Object Lock archive in Phase 4.",
    ),
    _c(
        "platform.db_least_privilege",
        "Least-privilege database roles",
        "Platform",
        L,
        DONE,
        2,
        "Separate migrator and runtime roles; grants verified against a privilege matrix.",
    ),
    _c(
        "platform.local_outbox",
        "Local email outbox",
        "Platform",
        L,
        DONE,
        2,
        "Invitation and reset emails are stored, not sent. Real delivery would need SES.",
    ),
    # --- Planned: local functionality --------------------------------------------------
    # --- Phase 6: implemented locally ---------------------------------------------------
    _c(
        "api.inventory",
        "API inventory and OWASP API Top 10 mapping",
        "API Security",
        L,
        DONE,
        6,
        "Generated from the live route table; a test fails if an endpoint is missing.",
    ),
    _c(
        "api.rate_limit",
        "Application rate limiting",
        "API Security",
        L,
        DONE,
        6,
        "PostgreSQL token buckets per IP and per account; WAF rate rules follow in Phase 5.",
    ),
    _c(
        "api.metrics",
        "Per-endpoint request, error and rejection metrics",
        "API Security",
        L,
        DONE,
        6,
        "Hourly counters by route template; no IPs, IDs or payloads stored.",
    ),
    _c(
        "api.ssrf_guard",
        "Outbound request (SSRF) guard",
        "API Security",
        L,
        DONE,
        6,
        "Ready for Phase 9 integrations; no endpoint fetches user-supplied URLs today.",
    ),
    _c(
        "platform.client_ip",
        "Trusted-proxy client IP resolution",
        "Edge Security",
        L,
        DONE,
        6,
        "X-Forwarded-For honoured only from the local proxy network; ALB subnets in Phase 4.",
    ),
    # --- Phase 7: security operations, implemented locally -------------------------------
    _c(
        "secops.events",
        "Security event pipeline",
        "Threats",
        L,
        DONE,
        7,
        "Append-only events from auth, authorization, rate limiting and HTTP analysis.",
    ),
    _c(
        "secops.http_analysis",
        "HTTP attack analysis (detect-only)",
        "Threats",
        L,
        DONE,
        7,
        "17 rules for injection, XSS, traversal, SSRF, scanning; records, never blocks.",
    ),
    _c(
        "secops.correlation",
        "Correlation rules",
        "Threats",
        L,
        DONE,
        7,
        "COR-001 to COR-007, run synchronously under the audit lock; exactly-once detections.",
    ),
    _c(
        "secops.incidents",
        "Incident response workflow",
        "Incident Response",
        L,
        DONE,
        7,
        "DETECTED to CLOSED with role rules, write-once evidence and an audited timeline.",
    ),
    _c(
        "secops.dashboard",
        "Security dashboard",
        "Dashboard",
        L,
        DONE,
        7,
        "Incidents, events, sources and traffic; live and simulated views never mixed.",
    ),
    _c(
        "vuln.management",
        "Vulnerability management",
        "Vulnerability Management",
        L,
        DONE,
        8,
        "Scans imported (make scan-import), de-duplicated, SLA due dates, triage, risk acceptance.",
    ),
    _c(
        "governance.threat_model",
        "Threat modeling (STRIDE / PASTA)",
        "Governance",
        L,
        DONE,
        10,
        "SentinelEdge's model loaded from the reviewed docs; application models built in the app.",
    ),
    _c(
        "governance.exceptions",
        "Risk exceptions and change management",
        "Governance",
        L,
        DONE,
        10,
        "Whoever asks cannot approve (service and database); exceptions expire; audited history.",
    ),
    _c(
        "ai.analysis",
        "AI security analysis (Amazon Bedrock)",
        "AI Security",
        L,
        PLAN,
        9,
        "Bedrock selected (ADR-0006). Output separates observed evidence from inference.",
    ),
    _c(
        "ai.approval",
        "Human approval for AI-proposed actions",
        "AI Security",
        L,
        PLAN,
        9,
        "AI can only create proposals; nothing executes without approval.",
    ),
    _c(
        "apps.inventory",
        "Protected application inventory",
        "Applications",
        L,
        DONE,
        7,
        "Owner, criticality and domain; measures not yet connected say which phase adds them.",
    ),
    _c(
        "devsecops.scanning",
        "SAST, SCA, secrets, IaC, container, DAST gates",
        "DevSecOps",
        L,
        DONE,
        8,
        "Semgrep, Bandit, Trivy, Gitleaks, Checkov, ZAP (authenticated) gate make scan and CI.",
    ),
    _c(
        "devsecops.sbom",
        "SBOM generation and tracking",
        "SBOM",
        L,
        DONE,
        8,
        "Syft CycloneDX for the API image, web image and source, stored per scan and commit.",
    ),
    _c(
        "governance.controls",
        "Security control matrix and posture score",
        "Compliance",
        L,
        DONE,
        10,
        "Coverage minus live signals; every point traces to controls or records; daily snapshots.",
    ),
    _c(
        "automation.tools",
        "Security automation CLI tools",
        "Automation",
        L,
        PLAN,
        11,
        "Reports, certificate inventory, API inventory, posture calculation.",
    ),
    # --- Planned: real AWS integrations --------------------------------------------------
    _c(
        "aws.network",
        "VPC, private subnets, security groups",
        "Network Security",
        R,
        PLAN,
        3,
        "Terraform-managed. Zero-cost resources first.",
    ),
    _c(
        "aws.compute",
        "ECS Fargate, internal ALB, RDS",
        "Platform",
        R,
        PLAN,
        4,
        "Private subnets only; database never publicly accessible.",
    ),
    _c(
        "aws.observability",
        "CloudWatch logs, metrics and alarms",
        "Audit Logs",
        R,
        PLAN,
        4,
        "Structured API and audit logs shipped to CloudWatch, with alarms on security signals.",
    ),
    _c(
        "aws.waf",
        "AWS WAF on CloudFront",
        "WAF",
        R,
        PLAN,
        5,
        "Rules changed only via Terraform; the dashboard reads state and raises change requests.",
    ),
    _c(
        "aws.edge",
        "CloudFront with VPC origin",
        "Edge Security",
        R,
        PLAN,
        5,
        "Internal ALB origin; no public origin to bypass.",
    ),
    _c(
        "aws.certificates",
        "ACM certificate monitoring",
        "Certificates",
        R,
        PLAN,
        5,
        "Read-only ACM API polling with expiry alerting.",
    ),
    _c(
        "aws.waf_logs",
        "WAF log ingestion",
        "Threats",
        R,
        PLAN,
        5,
        "Real WAF logs from CloudWatch, displayed alongside labelled simulated events.",
    ),
    # --- Simulations and demo data -----------------------------------------------------
    _c(
        "sim.attacks",
        "Attack event simulator",
        "Automation",
        S,
        DONE,
        7,
        "11 scenarios, in memory only: no network I/O, no target input, RFC 5737 addresses.",
    ),
    _c(
        "sim.waf_toggle",
        "In-dashboard WAF rule toggling",
        "WAF",
        S,
        DONE,
        7,
        "Simulation only. Real rule changes go through Terraform change requests.",
    ),
    _c(
        "demo.scenarios",
        "Interview demo mode and scenarios",
        "Automation",
        D,
        PLAN,
        12,
        "Five scripted scenarios on synthetic data.",
    ),
)
