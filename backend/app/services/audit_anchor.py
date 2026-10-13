"""Anchors of the audit chain's head, kept outside the database (ADR-0005, Phase 4).

A hash chain proves that the records it still has are unaltered, but not that none were removed
from the end: deleting the newest records leaves a shorter chain that still verifies. An anchor
records the head (its sequence number and hash) in an S3 bucket with Object Lock, where neither
the application nor anyone with the database can change or delete it during the retention
period. Checking the database against the latest anchor then catches a removed tail:

    export  verify the chain, then write {head_seq, head_hash, records} as a new object
    check   read the newest anchor; the anchored record must still exist with the same hash,
            and the chain must still verify

A broken chain is never anchored: anchoring it would vouch for a tampered state.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.clock import utcnow
from app.models.audit import AuditLog
from app.services.audit import GENESIS_HASH, verify_chain

SCHEMA_VERSION = 1
PREFIX = "anchors/"
MAX_ANCHOR_BYTES = 4096
_HASH = re.compile(r"^[0-9a-f]{64}$")
_FIELDS = {"schema", "head_seq", "head_hash", "records", "created_at", "environment"}


class AnchorError(Exception):
    """The chain cannot be anchored, or an anchor cannot be read or does not match."""


@dataclass(frozen=True)
class Anchor:
    head_seq: int
    head_hash: str
    records: int
    created_at: datetime
    environment: str

    @property
    def key(self) -> str:
        # Keys sort in time order, so the newest anchor is the greatest key.
        t = self.created_at.astimezone(UTC)
        return f"{PREFIX}{t:%Y/%m/%d}/{t:%Y%m%dT%H%M%S%fZ}-seq{self.head_seq:012d}.json"

    def to_json(self) -> bytes:
        return json.dumps(
            {
                "schema": SCHEMA_VERSION,
                "head_seq": self.head_seq,
                "head_hash": self.head_hash,
                "records": self.records,
                "created_at": self.created_at.astimezone(UTC).isoformat(),
                "environment": self.environment,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()

    @classmethod
    def from_json(cls, raw: bytes) -> Anchor:
        """Parse strictly: an anchor that does not look exactly like one is refused."""
        if len(raw) > MAX_ANCHOR_BYTES:
            raise AnchorError("the anchor object is too large")
        try:
            data = json.loads(raw)
        except (ValueError, UnicodeDecodeError) as exc:
            raise AnchorError("the anchor is not valid JSON") from exc
        if not isinstance(data, dict) or set(data) != _FIELDS:
            raise AnchorError("the anchor has unexpected or missing fields")
        if data["schema"] != SCHEMA_VERSION:
            raise AnchorError(f"unknown anchor schema {data['schema']!r}")
        head_seq, records = data["head_seq"], data["records"]
        if not all(type(v) is int and v >= 0 for v in (head_seq, records)):
            raise AnchorError("head_seq and records must be non-negative integers")
        if not isinstance(data["head_hash"], str) or not _HASH.match(data["head_hash"]):
            raise AnchorError("head_hash is not a SHA-256 hex digest")
        if not isinstance(data["environment"], str) or not isinstance(data["created_at"], str):
            raise AnchorError("environment and created_at must be strings")
        try:
            created = datetime.fromisoformat(data["created_at"])
        except ValueError as exc:
            raise AnchorError("created_at is not an ISO 8601 timestamp") from exc
        if created.tzinfo is None:
            raise AnchorError("created_at has no time zone")
        return cls(head_seq, data["head_hash"], records, created, data["environment"])


def export_anchor(
    db: Session, s3: Any, bucket: str, environment: str, now: datetime | None = None
) -> Anchor:
    result = verify_chain(db)
    if not result.intact:
        raise AnchorError(
            f"the audit chain is broken at seq={result.first_break_seq} ({result.problem}): "
            "a broken chain is never anchored"
        )
    anchor = Anchor(
        head_seq=result.head_seq,
        head_hash=result.head_hash,
        records=result.records_checked,
        created_at=now or utcnow(),
        environment=environment,
    )
    # The bucket's default Object Lock retention applies to every new object; this role can
    # neither shorten it nor delete objects.
    s3.put_object(
        Bucket=bucket,
        Key=anchor.key,
        Body=anchor.to_json(),
        ContentType="application/json",
        ChecksumAlgorithm="SHA256",
    )
    return anchor


def latest_anchor(s3: Any, bucket: str) -> Anchor | None:
    newest: str | None = None
    token: str | None = None
    while True:
        page = s3.list_objects_v2(
            Bucket=bucket, Prefix=PREFIX, **({"ContinuationToken": token} if token else {})
        )
        for obj in page.get("Contents", []):
            if newest is None or obj["Key"] > newest:
                newest = obj["Key"]
        if not page.get("IsTruncated"):
            break
        token = page["NextContinuationToken"]
    if newest is None:
        return None
    body = s3.get_object(Bucket=bucket, Key=newest)["Body"].read(MAX_ANCHOR_BYTES + 1)
    return Anchor.from_json(body)


def check_anchor(db: Session, anchor: Anchor) -> None:
    """Raise AnchorError unless the database still holds the anchored head, unchanged."""
    if anchor.head_seq == 0:
        if anchor.head_hash != GENESIS_HASH:
            raise AnchorError("an empty-chain anchor must carry the genesis hash")
    else:
        stored = db.scalar(select(AuditLog.record_hash).where(AuditLog.seq == anchor.head_seq))
        if stored is None:
            raise AnchorError(
                f"anchored record seq={anchor.head_seq} is missing: records were removed"
            )
        if stored != anchor.head_hash:
            raise AnchorError(f"record seq={anchor.head_seq} no longer matches its anchored hash")
    result = verify_chain(db)
    if not result.intact:
        raise AnchorError(f"the audit chain is broken at seq={result.first_break_seq}")
    if result.head_seq < anchor.head_seq:
        raise AnchorError("the chain is shorter than when it was anchored")
