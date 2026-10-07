"""Client IP resolution behind trusted proxies (threat T-ORG-02).

A spoofed X-Forwarded-For must never change the address used for rate limits and audit
records, unless the header was written by a proxy inside a configured trusted network.
"""

from __future__ import annotations

import ipaddress

import pytest
from fastapi import Request
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.core.client_ip import resolve_client_ip
from app.main import create_app
from tests.conftest import make_settings

pytestmark = pytest.mark.security

PROXIES = (ipaddress.ip_network("172.30.86.0/24"),)


@pytest.mark.parametrize(
    ("peer", "forwarded", "expected"),
    [
        # No trusted proxy in front: the header is ignored, the TCP peer is the client.
        ("203.0.113.5", "198.51.100.1", "203.0.113.5"),
        # Trusted proxy: the address it recorded is the client.
        ("172.30.86.2", "198.51.100.1", "198.51.100.1"),
        # A client-supplied entry before the proxy's own entry is ignored (spoofing attempt).
        ("172.30.86.2", "6.6.6.6, 198.51.100.1", "198.51.100.1"),
        # Chained trusted proxies are skipped.
        ("172.30.86.2", "198.51.100.1, 172.30.86.7", "198.51.100.1"),
        # Trusted proxy but no header: the proxy itself (e.g. an internal health check).
        ("172.30.86.2", None, "172.30.86.2"),
        # Garbage in the chain: stop at the last verified hop rather than trusting it.
        ("172.30.86.2", "198.51.100.1, not-an-ip", "172.30.86.2"),
        # Every hop trusted: the furthest verified one.
        ("172.30.86.2", "172.30.86.9", "172.30.86.9"),
        # IPv6 client behind the proxy.
        ("172.30.86.2", "2001:db8::1", "2001:db8::1"),
        # A non-IP peer (test clients, Unix sockets) is returned unchanged.
        ("testclient", "198.51.100.1", "testclient"),
    ],
)
def test_resolution(peer: str, forwarded: str | None, expected: str) -> None:
    assert resolve_client_ip(peer, forwarded, PROXIES) == expected


def test_nothing_is_trusted_by_default() -> None:
    assert resolve_client_ip("172.30.86.2", "198.51.100.1", ()) == "172.30.86.2"


@pytest.mark.parametrize("cidr", ["0.0.0.0/0", "::/0"])
def test_trusting_everyone_is_rejected(cidr: str) -> None:
    with pytest.raises(ValidationError, match="not permitted"):
        make_settings(trusted_proxy_cidrs=[cidr])


@pytest.mark.parametrize("cidr", ["not-a-network", "10.0.0.1/8"])
def test_invalid_networks_are_rejected(cidr: str) -> None:
    with pytest.raises(ValidationError, match="invalid trusted proxy network"):
        make_settings(trusted_proxy_cidrs=[cidr])


def test_proxy_networks_parse_from_environment_csv() -> None:
    settings = make_settings(trusted_proxy_cidrs="172.30.86.0/24, 10.0.0.0/16")
    assert settings.trusted_proxy_cidrs == ["172.30.86.0/24", "10.0.0.0/16"]


def test_rate_limiting_cannot_be_disabled_when_deployed() -> None:
    with pytest.raises(ValidationError, match="rate limiting cannot be disabled"):
        make_settings(
            environment="production",
            rate_limit_enabled=False,
            db_sslmode="verify-full",
            public_origins=["https://sentinel.example.com"],
            password_hash_memory_kib=19456,
            password_hash_time_cost=2,
        )


def _peer_seen_by_app(trusted: list[str], peer: str, forwarded: str) -> str:
    """The client address as a route handler sees it (inside every middleware)."""
    app = create_app(make_settings(trusted_proxy_cidrs=trusted))

    @app.get("/test/client-ip")
    def client_ip(request: Request) -> str:
        return request.client.host if request.client else ""

    with TestClient(app, client=(peer, 40000)) as c:
        response = c.get("/test/client-ip", headers={"X-Forwarded-For": forwarded})
    result: str = response.json()
    return result


def test_middleware_rewrites_client_only_for_trusted_peers() -> None:
    assert _peer_seen_by_app(["172.30.86.0/24"], "172.30.86.2", "198.51.100.1") == "198.51.100.1"
    assert _peer_seen_by_app(["172.30.86.0/24"], "203.0.113.5", "198.51.100.1") == "203.0.113.5"
    assert _peer_seen_by_app([], "172.30.86.2", "198.51.100.1") == "172.30.86.2"
