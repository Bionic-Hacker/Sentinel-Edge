"""Resolve the real client IP behind trusted reverse proxies (threat T-ORG-02).

`X-Forwarded-For` is attacker-controlled unless it was written by a proxy we trust. This
middleware honours it only when the direct TCP peer is inside `trusted_proxy_cidrs`, and then
walks the header right to left, skipping trusted proxies, so the first untrusted address is the
client. Anything a client prepends to the header is ignored.

It rewrites `scope["client"]`, so every consumer (rate limiting, audit records, access logs)
sees the same resolved address and none of them parses proxy headers itself.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable

from starlette.datastructures import Headers
from starlette.types import ASGIApp, Receive, Scope, Send

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def _parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def resolve_client_ip(
    peer: str | None, forwarded_for: str | None, trusted: Iterable[IPNetwork]
) -> str | None:
    networks = tuple(trusted)

    def is_trusted(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        return any(address in network for network in networks)

    peer_ip = _parse_ip(peer) if peer else None
    if peer_ip is None or not networks or not is_trusted(peer_ip) or not forwarded_for:
        return peer
    verified = peer_ip  # the furthest-left address whose report we can trust
    for hop in reversed(forwarded_for.split(",")):
        address = _parse_ip(hop)
        if address is None:
            # A malformed hop: nothing to its left can be trusted.
            break
        if not is_trusted(address):
            return str(address)
        verified = address
    # Every hop was a trusted proxy (or the chain broke): the furthest verified address.
    return str(verified)


class ClientIpMiddleware:
    def __init__(self, app: ASGIApp, trusted_proxy_cidrs: Iterable[str]) -> None:
        self.app = app
        self.trusted = tuple(ipaddress.ip_network(c) for c in trusted_proxy_cidrs)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and self.trusted:
            client = scope.get("client")
            peer, port = (client[0], client[1]) if client else (None, 0)
            resolved = resolve_client_ip(
                peer, Headers(scope=scope).get("x-forwarded-for"), self.trusted
            )
            if resolved is not None and resolved != peer:
                scope["client"] = (resolved, port)
        await self.app(scope, receive, send)
