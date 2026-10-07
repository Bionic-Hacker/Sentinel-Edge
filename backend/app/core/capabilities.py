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
    _c(
        "api.inventory",
        "API inventory and OWASP API Top 10 mapping",
        "API Security",
        L,
        PLAN,
        6,
        "Generated from the live route table, not hand-maintained.",
    ),
    _c(
        "api.rate_limit",
        "Application rate limiting",
        "API Security",
        L,
        PLAN,
        6,
        "Postgres-backed limiter; complements WAF rate-based rules.",
    ),
    _c(
        "secops.incidents",
        "Incident response workflow",
        "Incident Response",
        L,
        PLAN,
        7,
        "DETECTED to CLOSED state machine with evidence and timeline.",
    ),
    _c(
        "vuln.management",
        "Vulnerability management",
        "Vulnerability Management",
        L,
        PLAN,
        8,
        "Findings imported from real scanner output in CI.",
    ),
    _c(
        "governance.threat_model",
        "Threat modeling (STRIDE / PASTA)",
        "Governance",
        L,
        PLAN,
        10,
        "Initial SentinelEdge threat model exists as documentation in Phase 1.",
    ),
    _c(
        "governance.exceptions",
        "Risk exceptions and change management",
        "Governance",
        L,
        PLAN,
        10,
        "Requester, justification, compensating control, approver, expiry.",
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
        PLAN,
        6,
        "Owner, criticality, domain, WAF and certificate status per application.",
    ),
    _c(
        "devsecops.scanning",
        "SAST, SCA, secrets, IaC, container, DAST gates",
        "DevSecOps",
        L,
        PLAN,
        8,
        "Semgrep, Bandit, pip-audit, npm audit, Gitleaks, Checkov, Trivy, ZAP in CI.",
    ),
    _c(
        "devsecops.sbom",
        "SBOM generation and tracking",
        "SBOM",
        L,
        PLAN,
        8,
        "Syft SBOM per build, stored with the commit SHA and image digest.",
    ),
    _c(
        "governance.controls",
        "Security control matrix and posture score",
        "Compliance",
        L,
        PLAN,
        10,
        "Every score traces to the controls and evidence that produced it.",
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
        7,
        "Real WAF logs from CloudWatch, displayed alongside labelled simulated events.",
    ),
    # --- Planned: simulations and demo data -------------------------------------------
    _c(
        "sim.attacks",
        "Attack event simulator",
        "Automation",
        S,
        PLAN,
        7,
        "Generates labelled events against SentinelEdge only; never external targets.",
    ),
    _c(
        "sim.waf_toggle",
        "In-dashboard WAF rule toggling",
        "WAF",
        S,
        PLAN,
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
