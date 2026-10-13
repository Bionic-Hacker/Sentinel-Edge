"""The SPA gets the same security headers from CloudFront in AWS (Phase 5) as from nginx locally
(ADR-0011): one policy, two places, and a test that keeps them identical."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
NGINX = ROOT / "frontend" / "security-headers.conf"
EDGE = ROOT / "terraform" / "modules" / "edge" / "main.tf"


def _nginx_headers() -> dict[str, str]:
    pattern = re.compile(r'^add_header\s+([A-Za-z-]+)\s+"([^"]*)"\s+always;', re.M)
    return dict(pattern.findall(NGINX.read_text()))


def _edge_headers() -> dict[str, str]:
    block = re.search(r"spa_headers = \{(.*?)\n  \}", EDGE.read_text(), re.S)
    assert block, "terraform/modules/edge/main.tf must define local.spa_headers"
    return dict(re.findall(r'"([A-Za-z-]+)"\s*=\s*"([^"]*)"', block.group(1)))


@pytest.mark.skipif(not EDGE.exists(), reason="the repository's terraform/ is not present")
def test_edge_headers_match_nginx() -> None:
    nginx, edge = _nginx_headers(), _edge_headers()
    assert len(nginx) == 9
    assert edge == nginx


@pytest.mark.skipif(not EDGE.exists(), reason="the repository's terraform/ is not present")
def test_every_header_has_a_place_in_the_cloudfront_policy() -> None:
    """CloudFront takes CSP, HSTS, nosniff, frame and referrer options as dedicated settings and
    refuses them as custom headers; the rest must be listed as custom headers."""
    listed = re.search(r"custom_headers = \[(.*?)\]", EDGE.read_text())
    assert listed, "terraform/modules/edge/main.tf must define local.custom_headers"
    custom = set(re.findall(r'"([A-Za-z-]+)"', listed.group(1)))
    dedicated = {
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
    }
    assert custom | dedicated == set(_nginx_headers())
    assert not custom & dedicated
