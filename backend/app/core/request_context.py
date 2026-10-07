"""Who is calling, from where: captured once per request for audit records."""

from __future__ import annotations

import re

from fastapi import Request

from app.core.correlation import get_correlation_id
from app.services.audit import RequestContext

_UNPRINTABLE = re.compile(r"[^\x20-\x7e]")


def request_context(request: Request) -> RequestContext:
    user_agent = request.headers.get("user-agent")
    return RequestContext(
        # No proxy-header trust yet: this is the direct peer. Phase 4 trusts X-Forwarded-For
        # from the ALB's address range only (ADR-0001, T-ORG-02).
        source_ip=request.client.host if request.client else None,
        user_agent=_UNPRINTABLE.sub("?", user_agent)[:256] if user_agent else None,
        correlation_id=get_correlation_id(),
    )
