#!/usr/bin/env python3
"""Check the deployed edge from the internet, as a visitor or an attacker would (make edge-check;
Phase 5, ADR-0027). Standard library only. Every check prints PASS or FAIL; any FAIL exits 1.

    scripts/edge-check.py --url https://sentineledge.example.com \\
        --alb internal-….elb.amazonaws.com --cloudfront d111111abcdef8.cloudfront.net

Checks:
- pages and the API answer over HTTPS, and plain HTTP is redirected;
- TLS 1.2 or later is negotiated;
- the SPA's headers are exactly those in frontend/security-headers.conf;
- the API is ready, and keeps its own stricter headers;
- AWS WAF blocks an SQL injection and a Log4j probe at the edge;
- the internal ALB resolves only to private addresses and cannot be reached from here;
- the API is not served under any other host name (origin certificate and the ALB's host rule).

Probes are sent only to the URL given, which must be the owner's own platform.
"""

from __future__ import annotations

import argparse
import http.client
import ipaddress
import json
import re
import socket
import ssl
import sys
from pathlib import Path
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
HEADERS_FILE = ROOT / "frontend" / "security-headers.conf"
UA = "SentinelEdge-edge-check/1"
failures = 0


DOH = "https://dns.google/resolve"


def resolve(name: str) -> tuple[set[str], str]:
    """The name's addresses, and how they were found.

    Many home routers and filtering resolvers drop DNS answers that point at private addresses
    (DNS rebinding protection), so an internal ALB can look as if it does not exist. When the
    local resolver returns nothing, ask Google's DNS-over-HTTPS service instead: the question is
    what the public DNS says, not what this network lets through.
    """
    try:
        found = {i[4][0] for i in socket.getaddrinfo(name, 443, proto=socket.IPPROTO_TCP)}
    except socket.gaierror:
        found = set()
    if found:
        return found, "local resolver"
    url = f"{DOH}?{urlencode({'name': name, 'type': 'A'})}"
    try:
        # A fixed https:// URL built above; no caller-supplied scheme can reach urlopen.
        with urlopen(url, timeout=10) as response:  # noqa: S310
            answers = json.load(response).get("Answer", [])
    except (OSError, ValueError):
        return set(), "no answer (local resolver and DNS-over-HTTPS)"
    found = {a["data"] for a in answers if a.get("type") == 1}
    return found, "DNS-over-HTTPS (the local resolver hid it)"


def check(label: str, ok: bool, detail: str = "") -> None:
    global failures
    if not ok:
        failures += 1
    print(f"  {'PASS' if ok else 'FAIL'}  {label}{f'  ({detail})' if detail and not ok else ''}")


def request(
    host: str, path: str, *, https: bool = True, headers: dict[str, str] | None = None
) -> tuple[int, dict[str, str], bytes, str | None]:
    """One request, no redirects followed: status, lower-cased headers, body, TLS version."""
    context = ssl.create_default_context()
    conn: http.client.HTTPConnection = (
        http.client.HTTPSConnection(host, timeout=15, context=context)
        if https
        else http.client.HTTPConnection(host, timeout=15)
    )
    try:
        conn.request("GET", path, headers={"User-Agent": UA, **(headers or {})})
        response = conn.getresponse()
        body = response.read(65536)
        version = conn.sock.version() if https and isinstance(conn.sock, ssl.SSLSocket) else None
        return response.status, {k.lower(): v for k, v in response.getheaders()}, body, version
    finally:
        conn.close()


def nginx_headers() -> dict[str, str]:
    pattern = re.compile(r'^add_header\s+([A-Za-z-]+)\s+"([^"]*)"\s+always;', re.M)
    return {k.lower(): v for k, v in pattern.findall(HEADERS_FILE.read_text())}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--url", required=True, help="the platform, e.g. https://sentineledge.example.com"
    )
    parser.add_argument("--alb", required=True, help="the internal ALB's DNS name")
    parser.add_argument(
        "--cloudfront", required=True, help="the distribution's *.cloudfront.net name"
    )
    args = parser.parse_args()
    host = urlsplit(args.url).hostname or ""
    if not host or urlsplit(args.url).scheme != "https":
        sys.exit("edge-check: --url must be https://<host>")

    print(f"SentinelEdge edge check against {args.url}\n")

    print("Transport")
    status, headers, _, _ = request(host, "/", https=False)
    check(
        "plain HTTP is redirected to HTTPS",
        status in (301, 302, 307, 308)
        and headers.get("location", "").startswith(f"https://{host}"),
        f"HTTP {status}",
    )
    status, headers, body, version = request(host, "/")
    check(
        "the SPA is served over HTTPS", status == 200 and b"<html" in body.lower(), f"HTTP {status}"
    )
    check("TLS 1.2 or later is negotiated", version in ("TLSv1.2", "TLSv1.3"), str(version))

    print("SPA headers (identical to frontend/security-headers.conf)")
    for name, value in nginx_headers().items():
        check(name, headers.get(name) == value, f"got {headers.get(name)!r}")
    status, _, body, _ = request(host, "/incidents")
    check(
        "a client-side route serves the SPA",
        status == 200 and b"<html" in body.lower(),
        f"HTTP {status}",
    )

    print("API")
    status, headers, body, _ = request(host, "/api/v1/ready")
    check(
        "the API is ready (database reachable as the app role)",
        status == 200 and b'"ready"' in body,
        f"HTTP {status}",
    )
    check(
        "the API keeps its own CSP",
        headers.get("content-security-policy", "").startswith("default-src 'none'"),
        headers.get("content-security-policy", "missing"),
    )
    check(
        "HSTS on API responses", "max-age=63072000" in headers.get("strict-transport-security", "")
    )

    print("AWS WAF")
    probe = quote("1' OR '1'='1")
    status, _, _, _ = request(host, f"/api/v1/health?id={probe}")
    check("an SQL injection probe is blocked at the edge", status == 403, f"HTTP {status}")
    status, _, _, _ = request(
        host, "/api/v1/health", headers={"User-Agent": "${jndi:ldap://example.invalid/a}"}
    )
    check("a Log4j (JNDI) probe is blocked at the edge", status == 403, f"HTTP {status}")

    print("Private origin")
    addresses, source = resolve(args.alb)
    check(
        "the ALB resolves only to private addresses",
        bool(addresses) and all(ipaddress.ip_address(a).is_private for a in addresses),
        f"{', '.join(sorted(addresses)) or 'none'} via {source}",
    )
    reachable = False
    for address in addresses:
        try:
            with socket.create_connection((address, 443), timeout=3):
                reachable = True
        except OSError:
            pass
    # With no addresses there is nothing to test, so this cannot pass on an empty lookup.
    check("the ALB cannot be reached from the internet", bool(addresses) and not reachable)
    # CloudFront forwards the Host header: under any other name the origin's certificate does not
    # match (502 from CloudFront) or the ALB's host rule refuses it (404). Either way, no API.
    status, _, body, _ = request(args.cloudfront, "/api/v1/health")
    check(
        "the API is not served under any other host name",
        status in (404, 502) and b'"ok"' not in body,
        f"HTTP {status}",
    )

    print(f"\n{'All edge checks passed.' if failures == 0 else f'{failures} check(s) FAILED.'}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
