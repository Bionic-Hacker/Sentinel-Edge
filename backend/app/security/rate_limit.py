"""PostgreSQL token-bucket rate limiter (ADR-0004, ADR-0017).

Each check is ONE atomic statement: refill the bucket for the time elapsed, spend a token if one
is available, and report the outcome. `INSERT ... ON CONFLICT DO UPDATE` locks the row, so
concurrent requests on different API tasks serialise on the bucket and can never both spend the
last token. Time comes from the database clock, so every task agrees on it.

Checks run on their own short connection and commit immediately: a request that later fails and
rolls back must still have spent its token, or failed requests would be free to repeat.
"""

from __future__ import annotations

import logging
import math
import random
from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

from app.core.api_policy import RateLimitPolicy
from app.models.audit import AuditResult
from app.services import audit
from app.services.audit import AuditAction, RequestContext

logger = logging.getLogger("sentineledge.ratelimit")

# Idle buckets refill to full; after a day untouched they carry no information. Pruned on a
# small fraction of checks (and by `python -m app.cli prune-rate-limits`).
PRUNE_PROBABILITY = 0.002

_CHECK = text(
    """
    INSERT INTO sentinel.rate_limit_buckets AS b
        (bucket_key, tokens, updated_at, last_allowed, denied_since)
    VALUES (:key, :capacity - 1, now(), true, NULL)
    ON CONFLICT (bucket_key) DO UPDATE SET
        tokens = CASE
            WHEN LEAST(:capacity, b.tokens + EXTRACT(EPOCH FROM now() - b.updated_at) * :rate) >= 1
            THEN LEAST(:capacity, b.tokens + EXTRACT(EPOCH FROM now() - b.updated_at) * :rate) - 1
            ELSE LEAST(:capacity, b.tokens + EXTRACT(EPOCH FROM now() - b.updated_at) * :rate)
        END,
        last_allowed =
            LEAST(:capacity, b.tokens + EXTRACT(EPOCH FROM now() - b.updated_at) * :rate) >= 1,
        denied_since = CASE
            WHEN LEAST(:capacity, b.tokens + EXTRACT(EPOCH FROM now() - b.updated_at) * :rate) >= 1
            THEN NULL
            ELSE COALESCE(b.denied_since, now())
        END,
        updated_at = now()
    RETURNING tokens, last_allowed, (denied_since = updated_at) AS first_denial
    """
)
_PRUNE = text("DELETE FROM sentinel.rate_limit_buckets WHERE updated_at < now() - interval '1 day'")


@dataclass(frozen=True)
class Decision:
    allowed: bool
    limit: int
    remaining: int
    retry_after_s: int  # seconds until one token is available (0 when allowed)
    reset_s: int  # seconds until the bucket is full again
    first_denial: bool  # the first denial since this bucket last allowed a request

    def headers(self) -> dict[str, str]:
        """IETF draft RateLimit header fields (draft-ietf-httpapi-ratelimit-headers)."""
        values = {
            "RateLimit-Limit": str(self.limit),
            "RateLimit-Remaining": str(self.remaining),
            "RateLimit-Reset": str(self.reset_s),
        }
        if not self.allowed:
            values["Retry-After"] = str(max(1, self.retry_after_s))
        return values


class RateLimiter:
    def __init__(self, session_factory: sessionmaker[Session], *, enabled: bool = True) -> None:
        self.session_factory = session_factory
        self.enabled = enabled

    def check(self, policy: RateLimitPolicy, subject: str) -> Decision | None:
        """Spend one token from `policy`'s bucket for `subject`. None when limiting is off."""
        if not self.enabled:
            return None
        rate = policy.refill_per_second
        with self.session_factory() as db:
            params = {
                "key": f"{policy.name}|{subject}"[:200],
                "capacity": policy.capacity,
                "rate": rate,
            }
            row = db.execute(_CHECK, params).one()
            # Not security relevant: only decides when to delete idle buckets.
            if random.random() < PRUNE_PROBABILITY:  # noqa: S311  # nosec B311
                db.execute(_PRUNE)
            db.commit()
        tokens = float(row.tokens)
        allowed = bool(row.last_allowed)
        first_denial = bool(row.first_denial)
        return Decision(
            allowed=allowed,
            limit=policy.capacity,
            remaining=max(0, math.floor(tokens)),
            retry_after_s=0 if allowed else math.ceil((1 - tokens) / rate),
            reset_s=math.ceil((policy.capacity - tokens) / rate),
            first_denial=first_denial and not allowed,
        )

    def record_denial(
        self,
        policy: RateLimitPolicy,
        *,
        actor: object,
        ctx: RequestContext,
        endpoint: str,
    ) -> None:
        """Audit the first denial of a run (later denials are counted in API metrics instead,
        so a flood cannot also flood the audit log)."""
        with self.session_factory() as db:
            audit.record(
                db,
                action=AuditAction.RATE_LIMITED,
                result=AuditResult.DENIED,
                actor=actor,  # type: ignore[arg-type]  # User or a label
                ctx=ctx,
                resource_type="endpoint",
                resource_id=endpoint,
                details={
                    "policy": policy.name,
                    "scope": policy.scope.value,
                    "limit": policy.description,
                },
            )
            db.commit()
        logger.warning(
            "rate_limited",
            extra={"policy": policy.name, "scope": policy.scope.value, "endpoint": endpoint},
        )

    def prune(self) -> int:
        with self.session_factory() as db:
            result = db.execute(_PRUNE)
            db.commit()
        return int(getattr(result, "rowcount", 0) or 0)
