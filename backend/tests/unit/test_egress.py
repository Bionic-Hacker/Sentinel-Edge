"""SSRF guard for outbound requests (OWASP API7)."""

from __future__ import annotations

import pytest

from app.security.egress import EgressDeniedError, check_outbound_url

pytestmark = pytest.mark.security


def resolves_to(*addresses: str):  # type: ignore[no-untyped-def]
    return lambda _host: list(addresses)


def test_public_https_destination_is_approved() -> None:
    approved = check_outbound_url(
        "https://bedrock-runtime.us-east-1.amazonaws.com/model/x/invoke",
        resolver=resolves_to("52.94.0.10"),
    )
    assert approved.host == "bedrock-runtime.us-east-1.amazonaws.com"
    assert approved.addresses == ("52.94.0.10",)  # callers connect to these, not a new lookup


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("http://example.com/", "only https"),
        ("file:///etc/passwd", "only https"),
        ("gopher://example.com/", "only https"),
        ("https://user:pass@example.com/", "credentials"),
        ("https://example.com:8443/", "default https port"),
        ("https:///no-host", "host is required"),
    ],
)
def test_url_shape_is_restricted(url: str, reason: str) -> None:
    with pytest.raises(EgressDeniedError, match=reason):
        check_outbound_url(url, resolver=resolves_to("93.184.216.34"))


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",  # loopback
        "10.1.2.3",  # RFC 1918
        "172.30.86.2",  # this stack's own edge network
        "192.168.1.1",
        "169.254.169.254",  # cloud instance metadata service
        "100.64.0.1",  # carrier-grade NAT
        "0.0.0.0",  # noqa: S104 - unspecified address, a test input, not a bind
        "224.0.0.1",  # multicast
        "::1",
        "fd00::1",  # unique-local IPv6
        "fe80::1",  # link-local IPv6
        "::ffff:127.0.0.1",  # IPv4-mapped loopback
        "::ffff:169.254.169.254",  # IPv4-mapped metadata service
        "2002:a9fe:a9fe::1",  # 6to4 wrapping 169.254.169.254
    ],
)
def test_internal_addresses_are_refused(address: str) -> None:
    with pytest.raises(EgressDeniedError, match="non-public"):
        check_outbound_url("https://innocent.example.com/", resolver=resolves_to(address))


def test_one_internal_answer_is_enough_to_refuse() -> None:
    """DNS can return several records; an attacker only needs one to be internal."""
    with pytest.raises(EgressDeniedError, match="non-public"):
        check_outbound_url(
            "https://mixed.example.com/", resolver=resolves_to("93.184.216.34", "10.0.0.5")
        )


@pytest.mark.parametrize(
    "url", ["https://127.0.0.1/", "https://[::1]/", "https://169.254.169.254/latest/meta-data/"]
)
def test_ip_literals_are_checked_without_dns(url: str) -> None:
    def no_dns(_host: str) -> list[str]:
        raise AssertionError("IP literals must not be resolved")

    with pytest.raises(EgressDeniedError, match="non-public"):
        check_outbound_url(url, resolver=no_dns)


def test_allow_list_is_enforced_before_resolution() -> None:
    allowed = frozenset({"bedrock-runtime.us-east-1.amazonaws.com"})
    with pytest.raises(EgressDeniedError, match="allow-list"):
        check_outbound_url("https://evil.example.com/", allowed_hosts=allowed)


def test_unresolvable_and_empty_answers_are_refused() -> None:
    def fails(_host: str) -> list[str]:
        raise OSError("NXDOMAIN")

    with pytest.raises(EgressDeniedError, match="did not resolve"):
        check_outbound_url("https://missing.example.com/", resolver=fails)
    with pytest.raises(EgressDeniedError, match="did not resolve"):
        check_outbound_url("https://empty.example.com/", resolver=resolves_to())


def test_invalid_port_and_bad_resolver_output_are_refused() -> None:
    with pytest.raises(EgressDeniedError, match="invalid port"):
        check_outbound_url("https://example.com:99999/")
    with pytest.raises(EgressDeniedError, match="invalid address"):
        check_outbound_url("https://example.com/", resolver=resolves_to("not-an-ip"))
