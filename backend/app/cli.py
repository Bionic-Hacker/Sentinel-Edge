"""Operator command line, run inside the API container (`make create-admin`, `make outbox`,
`make verify-audit`). It uses the same database role and settings as the API: no extra privilege.

    python -m app.cli create-admin --email admin@example.com
    python -m app.cli outbox [--limit 5]
    python -m app.cli verify-audit
    python -m app.cli import-scan --application sentineledge < bundle.json   (make scan-import)
"""

from __future__ import annotations

import argparse
import json
import re
import secrets
import sys
from collections.abc import Sequence
from typing import TextIO

from pydantic import EmailStr, TypeAdapter, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.db.session import build_engine, build_session_factory
from app.models.audit import AuditResult
from app.models.outbox import OutboxMessage
from app.models.user import Role, User
from app.models.vulnerability import ScanSource
from app.schemas.vulnerabilities import ScanReport
from app.security.passwords import PasswordHasher
from app.security.rate_limit import RateLimiter
from app.services import audit
from app.services.audit import SYSTEM_CONTEXT, AuditAction, verify_chain
from app.services.vulnerabilities import ScanImportError, import_scan

CLI_ACTOR = "system:cli"
_email = TypeAdapter(EmailStr)


def create_admin(db: Session, settings: Settings, email: str, name: str, out: TextIO) -> int:
    try:
        normalized = str(_email.validate_python(email)).strip().lower()
    except ValidationError:
        print(f"error: not a valid email address: {email!r}", file=sys.stderr)
        return 2
    if db.scalar(select(User.id).where(User.email == normalized)) is not None:
        print(f"error: a user with email {normalized} already exists", file=sys.stderr)
        return 1

    # No default credentials: a random one-time password the admin must replace at first login,
    # followed by mandatory MFA enrollment (ADMIN requires MFA).
    password = secrets.token_urlsafe(18)
    user = User(
        email=normalized,
        display_name=name,
        role=Role.ADMIN,
        password_hash=PasswordHasher(settings).hash(password),
        must_change_password=True,
    )
    db.add(user)
    db.flush()
    audit.record(
        db,
        action=AuditAction.USER_CREATED,
        result=AuditResult.SUCCESS,
        actor=CLI_ACTOR,
        ctx=SYSTEM_CONTEXT,
        resource_type="user",
        resource_id=str(user.id),
        details={"email": normalized, "role": Role.ADMIN.value, "via": "cli"},
    )
    db.commit()
    print(f"Created ADMIN {normalized}", file=out)
    print(f"One-time password: {password}", file=out)
    print(
        "It is shown only once. At first sign-in you must set a new password and enroll "
        "two-factor authentication.",
        file=out,
    )
    return 0


def show_outbox(db: Session, limit: int, out: TextIO) -> int:
    messages = db.scalars(
        select(OutboxMessage).order_by(OutboxMessage.created_at.desc()).limit(limit)
    ).all()
    if not messages:
        print("The local outbox is empty.", file=out)
        return 0
    for message in reversed(messages):
        print(f"--- {message.created_at:%Y-%m-%d %H:%M:%S %Z}  to: {message.recipient}", file=out)
        print(f"Subject: {message.subject}\n\n{message.body}\n", file=out)
    return 0


def verify_audit(db: Session, out: TextIO) -> int:
    result = verify_chain(db)
    if result.intact:
        print(f"Audit chain intact: {result.records_checked} records.", file=out)
        print(f"Head hash: {result.head_hash}", file=out)
        return 0
    print(
        f"AUDIT CHAIN BROKEN at record seq={result.first_break_seq}: {result.problem}. "
        f"{result.records_checked} records checked.",
        file=out,
    )
    return 1


MAX_IMPORT_BYTES = 64 * 1024 * 1024
_ACTOR = re.compile(r"^[A-Za-z0-9@._+-]{1,100}$")
_BRANCH = re.compile(r"^[A-Za-z0-9._/-]{1,200}$")
_SBOM_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")


def import_scan_bundle(
    db: Session,
    stdin: TextIO,
    *,
    application: str,
    source: str,
    commit: str | None,
    branch: str | None,
    actor: str,
    out: TextIO,
) -> int:
    """Import {"findings": <the gate's findings.json>, "sboms": {"api": <CycloneDX>, ...}}."""
    if commit is not None and not re.fullmatch(r"[0-9a-f]{40}", commit):
        print("error: --commit must be a full 40-character commit SHA", file=sys.stderr)
        return 2
    if branch is not None and not _BRANCH.fullmatch(branch):
        print("error: --branch has unexpected characters", file=sys.stderr)
        return 2
    if not _ACTOR.fullmatch(actor):
        print("error: --actor must be a short name or email address", file=sys.stderr)
        return 2
    text = stdin.read(MAX_IMPORT_BYTES + 1)
    if len(text) > MAX_IMPORT_BYTES:
        print(f"error: the import is larger than {MAX_IMPORT_BYTES} bytes", file=sys.stderr)
        return 2
    try:
        bundle = json.loads(text)
        if not isinstance(bundle, dict):
            raise ValueError("the bundle must be a JSON object")
        report = ScanReport.model_validate(bundle.get("findings"))
        sboms = bundle.get("sboms") or {}
        if not isinstance(sboms, dict) or not all(_SBOM_NAME.fullmatch(k) for k in sboms):
            raise ValueError("sboms must map artifact names (api, web, source) to documents")
        scan = import_scan(
            db,
            application_slug=application,
            report=report,
            sboms=sboms,
            source=ScanSource(source),
            commit_sha=commit,
            branch=branch,
            actor_label=f"cli:{actor}",
        )
        db.commit()
    except (ValueError, ScanImportError) as exc:  # ValidationError and JSONDecodeError too
        db.rollback()
        print(f"error: import refused, nothing stored: {exc}", file=sys.stderr)
        return 1
    summary = scan.summary
    print(
        f"Imported {scan.reference} for {application}: {summary['total']} findings "
        f"({summary['new']} new, {summary['reopened']} reopened, {summary['fixed']} fixed, "
        f"{summary['unchanged']} unchanged); SBOMs: {', '.join(summary['sboms']) or 'none'}; "
        f"gate {'passed' if scan.gate_passed else 'FAILED'}.",
        file=out,
    )
    if summary["acceptances_expired"]:
        print(f"{summary['acceptances_expired']} risk acceptances expired.", file=out)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m app.cli", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    admin = commands.add_parser("create-admin", help="create an ADMIN with a one-time password")
    admin.add_argument("--email", required=True)
    admin.add_argument("--name", default="Administrator")
    box = commands.add_parser("outbox", help="show recent local outbox messages")
    box.add_argument("--limit", type=int, default=5)
    commands.add_parser("verify-audit", help="verify the audit log hash chain")
    commands.add_parser("prune-rate-limits", help="delete rate-limit buckets idle for a day")
    scan = commands.add_parser("import-scan", help="import scan results and SBOMs from stdin")
    scan.add_argument("--application", default="sentineledge", help="application slug")
    scan.add_argument("--source", choices=[s.value for s in ScanSource], default="local")
    scan.add_argument("--commit", help="full commit SHA the scan ran on")
    scan.add_argument("--branch")
    scan.add_argument("--actor", default="operator", help="who ran the import")
    return parser


def main(
    argv: Sequence[str] | None = None,
    settings: Settings | None = None,
    out: TextIO = sys.stdout,
    stdin: TextIO = sys.stdin,
) -> int:
    args = build_parser().parse_args(argv)
    settings = settings or get_settings()
    engine = build_engine(settings)
    try:
        with build_session_factory(engine)() as db:
            if args.command == "create-admin":
                return create_admin(db, settings, args.email, args.name, out)
            if args.command == "outbox":
                return show_outbox(db, max(1, min(args.limit, 50)), out)
            if args.command == "import-scan":
                return import_scan_bundle(
                    db,
                    stdin,
                    application=args.application,
                    source=args.source,
                    commit=args.commit,
                    branch=args.branch,
                    actor=args.actor,
                    out=out,
                )
            if args.command == "prune-rate-limits":
                removed = RateLimiter(build_session_factory(engine)).prune()
                print(f"Removed {removed} idle rate-limit buckets.", file=out)
                return 0
            return verify_audit(db, out)
    finally:
        engine.dispose()


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
