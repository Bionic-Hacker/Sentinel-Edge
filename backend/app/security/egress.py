"""Outbound request guard against SSRF (OWASP API7).

No endpoint fetches a caller-supplied URL today. Any future code that makes an outbound request
(Phase 9 AI integrations, webhooks) must pass the destination through `check_outbound_url`
first. It enforces:

* HTTPS only, default port only, no credentials embedded in the URL;
* an explicit host allow-list when one is given (preferred over deny-lists);
* every address the host resolves to must be public: loopback, private (RFC 1918), link-local
  (including the cloud metadata service at 169.254.169.254), carrier-grade NAT, multicast,
  reserved, unspecified, unique-local IPv6 and IPv4-mapped/6to4 forms of all of these are refused.

It returns the validated addresses. Callers must connect to one of THOSE addresses (with the
original host name for TLS verification), not resolve the name again: a second lookup could
return a different, internal address (DNS rebinding).
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from urllib.parse import urlsplit

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Resolver = Callable[[str], Iterable[str]]

_CGNAT = ipaddress.ip_network("100.64.0.0/10")


class EgressDeniedError(ValueError):
    """The destination is not allowed. The message is safe to log, not to show users."""


@dataclass(frozen=True)
class ApprovedDestination:
    host: str
    port: int
    addresses: tuple[str, ...]


def system_resolver(host: str) -> list[str]:
    return [str(info[4][0]) for info in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)]


def _embedded_ipv4(address: IPAddress) -> ipaddress.IPv4Address | None:
    if isinstance(address, ipaddress.IPv6Address):
        return address.ipv4_mapped or address.sixtofour
    return None


def is_public_address(address: IPAddress) -> bool:
    embedded = _embedded_ipv4(address)
    if embedded is not None:
        return is_public_address(embedded)
    if isinstance(address, ipaddress.IPv4Address) and address in _CGNAT:
        return False
    return address.is_global and not (
        address.is_multicast or address.is_reserved or address.is_unspecified
    )


def check_outbound_url(
    url: str,
    *,
    allowed_hosts: frozenset[str] | None = None,
    resolver: Resolver = system_resolver,
) -> ApprovedDestination:
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise EgressDeniedError("only https destinations are allowed")
    if parts.username is not None or parts.password is not None:
        raise EgressDeniedError("credentials in URLs are not allowed")
    host = (parts.hostname or "").rstrip(".").lower()
    if not host:
        raise EgressDeniedError("a host is required")
    try:
        port = parts.port or 443
    except ValueError as exc:
        raise EgressDeniedError("invalid port") from exc
    if port != 443:
        raise EgressDeniedError("only the default https port is allowed")
    if allowed_hosts is not None and host not in allowed_hosts:
        raise EgressDeniedError(f"host {host!r} is not on the allow-list")

    try:
        literal: IPAddress | None = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        candidates = [str(literal)]
    else:
        try:
            candidates = list(resolver(host))
        except OSError as exc:
            raise EgressDeniedError(f"host {host!r} did not resolve") from exc
    if not candidates:
        raise EgressDeniedError(f"host {host!r} did not resolve")

    for candidate in candidates:
        try:
            address = ipaddress.ip_address(candidate.split("%", 1)[0])
        except ValueError as exc:
            raise EgressDeniedError("resolver returned an invalid address") from exc
        if not is_public_address(address):
            # Every address must be public: one internal answer is enough to refuse.
            raise EgressDeniedError(f"host {host!r} resolves to a non-public address")
    return ApprovedDestination(host=host, port=port, addresses=tuple(candidates))
