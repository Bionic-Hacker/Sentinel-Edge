"""Audit-chain anchors in S3 Object Lock (ADR-0005, Phase 4): the tail deletion a hash chain
alone cannot see. No network: a small in-memory S3 stands in for the bucket, refusing to
overwrite an object, as Object Lock would."""

from __future__ import annotations

import io
import json
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from app.cli import main
from app.services.audit_anchor import Anchor, AnchorError
from tests.conftest import make_settings
from tests.helpers import create_user, login

pytestmark = [pytest.mark.security, pytest.mark.db]

BUCKET = "sentineledge-dev-audit-anchors-test"


class LockedBucket:
    """Just enough of S3 for anchors: put (never overwrite), list, get. No delete exists."""

    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}
        self.puts: list[dict[str, Any]] = []

    def put_object(self, **kw: Any) -> dict[str, Any]:
        assert kw["Bucket"] == BUCKET
        assert kw["Key"] not in self.objects, "Object Lock: an anchor is never overwritten"
        self.puts.append(kw)
        self.objects[kw["Key"]] = kw["Body"]
        return {}

    def list_objects_v2(self, **kw: Any) -> dict[str, Any]:
        keys = sorted(k for k in self.objects if k.startswith(kw["Prefix"]))
        return {"Contents": [{"Key": k} for k in keys], "IsTruncated": False}

    def get_object(self, **kw: Any) -> dict[str, Any]:
        return {"Body": io.BytesIO(self.objects[kw["Key"]])}


def _run(bucket: LockedBucket, *argv: str, **settings: Any) -> tuple[int, str]:
    out = io.StringIO()
    code = main(
        list(argv),
        settings=make_settings(audit_anchor_bucket=BUCKET, **settings),
        out=out,
        s3=bucket,
    )
    return code, out.getvalue()


def _three_records(db_app: FastAPI, db_client: TestClient) -> None:
    create_user(db_app, "analyst@example.com")
    for _ in range(3):
        login(db_client, "analyst@example.com", "wrong password here")


def _tamper(migrator_engine: Engine, statement: str) -> None:
    with migrator_engine.begin() as conn:
        conn.execute(
            text("ALTER TABLE sentinel.audit_log DISABLE TRIGGER audit_log_no_update_delete")
        )
        conn.execute(text(statement))
        conn.execute(
            text("ALTER TABLE sentinel.audit_log ENABLE TRIGGER audit_log_no_update_delete")
        )


def test_export_writes_the_verified_head_and_check_matches(
    db_app: FastAPI, db_client: TestClient
) -> None:
    _three_records(db_app, db_client)
    bucket = LockedBucket()

    code, output = _run(bucket, "audit-anchor", "export")
    assert code == 0, output
    assert "Anchored seq=" in output
    assert "(3 records)" in output
    (put,) = bucket.puts
    assert put["ChecksumAlgorithm"] == "SHA256"
    assert put["Key"].startswith("anchors/")
    assert put["Key"].endswith(".json")
    anchor = json.loads(put["Body"])
    assert anchor["records"] == 3
    assert len(anchor["head_hash"]) == 64

    code, output = _run(bucket, "audit-anchor", "check")
    assert code == 0, output
    assert "matches the anchor" in output


def test_check_catches_records_removed_from_the_end(
    db_app: FastAPI, db_client: TestClient, migrator_engine: Engine
) -> None:
    """The attack the chain alone cannot see: the shorter chain still verifies."""
    _three_records(db_app, db_client)
    bucket = LockedBucket()
    assert _run(bucket, "audit-anchor", "export")[0] == 0

    _tamper(
        migrator_engine,
        "DELETE FROM sentinel.audit_log WHERE seq = (SELECT max(seq) FROM sentinel.audit_log)",
    )
    assert "intact" in _verify()  # the chain on its own is fooled

    code, output = _run(bucket, "audit-anchor", "check")
    assert code == 1
    assert "AUDIT ANCHOR FAILED" in output
    assert "records were removed" in output


def test_check_catches_a_rewritten_head(
    db_app: FastAPI, db_client: TestClient, migrator_engine: Engine
) -> None:
    _three_records(db_app, db_client)
    bucket = LockedBucket()
    assert _run(bucket, "audit-anchor", "export")[0] == 0

    _tamper(
        migrator_engine,
        "UPDATE sentinel.audit_log SET record_hash = repeat('a', 64) "
        "WHERE seq = (SELECT max(seq) FROM sentinel.audit_log)",
    )
    code, output = _run(bucket, "audit-anchor", "check")
    assert code == 1
    assert "no longer matches its anchored hash" in output


def test_a_broken_chain_is_never_anchored(
    db_app: FastAPI, db_client: TestClient, migrator_engine: Engine
) -> None:
    _three_records(db_app, db_client)
    _tamper(migrator_engine, "UPDATE sentinel.audit_log SET result = 'success' WHERE seq = 2")
    bucket = LockedBucket()

    code, output = _run(bucket, "audit-anchor", "export")
    assert code == 1
    assert "never anchored" in output
    assert bucket.objects == {}


def test_check_uses_the_newest_anchor(db_app: FastAPI, db_client: TestClient) -> None:
    _three_records(db_app, db_client)
    bucket = LockedBucket()
    assert _run(bucket, "audit-anchor", "export")[0] == 0
    login(db_client, "analyst@example.com", "wrong password here")
    assert _run(bucket, "audit-anchor", "export")[0] == 0

    code, output = _run(bucket, "audit-anchor", "check")
    assert code == 0
    newest = Anchor.from_json(bucket.objects[max(bucket.objects)])
    assert newest.records == 4
    assert f"seq={newest.head_seq}" in output


def test_without_a_bucket_or_an_anchor_nothing_passes_silently(db_app: FastAPI) -> None:
    out = io.StringIO()
    assert main(["audit-anchor", "export"], settings=make_settings(), out=out) == 2
    assert "SENTINEL_AUDIT_ANCHOR_BUCKET is not set" in out.getvalue()

    code, output = _run(LockedBucket(), "audit-anchor", "check")
    assert code == 1
    assert "No anchor yet" in output


def _verify() -> str:
    out = io.StringIO()
    main(["verify-audit"], settings=make_settings(), out=out)
    return out.getvalue()


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (b"not json", "not valid JSON"),
        (b'{"schema":1}', "unexpected or missing fields"),
        (
            b'{"schema":2,"head_seq":1,"head_hash":"' + b"a" * 64 + b'","records":1,'
            b'"created_at":"2026-10-12T00:00:00+00:00","environment":"dev"}',
            "unknown anchor schema",
        ),
        (
            b'{"schema":1,"head_seq":-1,"head_hash":"' + b"a" * 64 + b'","records":1,'
            b'"created_at":"2026-10-12T00:00:00+00:00","environment":"dev"}',
            "non-negative integers",
        ),
        (
            b'{"schema":1,"head_seq":1,"head_hash":"xyz","records":1,'
            b'"created_at":"2026-10-12T00:00:00+00:00","environment":"dev"}',
            "SHA-256",
        ),
        (
            b'{"schema":1,"head_seq":1,"head_hash":"' + b"a" * 64 + b'","records":1,'
            b'"created_at":"2026-10-12T00:00:00","environment":"dev"}',
            "no time zone",
        ),
        (b"{" + b" " * 5000 + b"}", "too large"),
    ],
)
def test_anchors_are_parsed_strictly(raw: bytes, message: str) -> None:
    with pytest.raises(AnchorError, match=message):
        Anchor.from_json(raw)


def test_anchor_keys_sort_by_time() -> None:
    early = Anchor(5, "a" * 64, 5, datetime(2026, 10, 12, 9, 0, tzinfo=UTC), "dev")
    late = Anchor(4, "b" * 64, 4, datetime(2026, 10, 12, 10, 0, tzinfo=UTC), "dev")
    assert late.key > early.key
    assert Anchor.from_json(early.to_json()) == early
