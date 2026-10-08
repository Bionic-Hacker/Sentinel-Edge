"""HTTP security headers applied to every API response.

These mirror — and are intentionally duplicated by — the CloudFront response-headers policy
planned for Phase 5 (ADR-0011). Duplication is deliberate defense in depth: the API stays
safe if it is ever reached without the edge (local dev, misrouted traffic, origin bypass).

The API serves JSON only, so its CSP is the most restrictive possible. The SPA's CSP is set
separately by its web server (frontend/nginx.conf) and later by CloudFront.
"""

from __future__ import annotations

API_SECURITY_HEADERS: dict[str, str] = {
    # JSON API: nothing may be loaded, framed, or executed from a response.
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    # Two years, all subdomains. `preload` deferred until the domain is chosen (Phase 5).
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": (
        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), "
        "microphone=(), payment=(), usb=(), interest-cohort=()"
    ),
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
    # Security data must never be cached by browsers or shared caches.
    "Cache-Control": "no-store",
}
