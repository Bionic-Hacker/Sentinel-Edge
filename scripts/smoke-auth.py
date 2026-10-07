#!/usr/bin/env python3
"""End-to-end smoke test of authentication, authorization, auditing and API security, run
against the live local stack through the nginx edge exactly as a browser would use it.

    make smoke            # stack must be running (make dev)

Each run creates its own uniquely named admin and analyst (synthetic @example.com addresses) via
the API container's CLI, so it can be repeated. It deliberately locks the analyst account it
created, and exhausts this machine's readiness-probe rate limit, which refills within a minute.
Nothing else is modified.

Note on cookies: browsers send `Secure` cookies to http://localhost; this HTTP client does not,
so the script carries the refresh cookie explicitly. That reproduces browser behaviour; it does
not relax anything on the server.
"""

from __future__ import annotations

import os
import re
import secrets
import shlex
import subprocess
import sys
from datetime import UTC, datetime, timedelta

import httpx2 as httpx
import pyotp

BASE = os.environ.get("SMOKE_BASE_URL", "http://localhost:8080")
CLI = shlex.split(os.environ.get("SMOKE_CLI", "docker compose exec -T api python -m app.cli"))
HEADERS = {"Origin": BASE, "X-SentinelEdge-CSRF": "1"}
COOKIE = "__Host-sentinel_refresh"

passed = 0


def check(label: str, condition: bool) -> None:
    global passed
    if not condition:
        print(f"  FAIL  {label}")
        sys.exit(1)
    passed += 1
    print(f"  PASS  {label}")


def cli(*args: str) -> str:
    result = subprocess.run([*CLI, *args], capture_output=True, text=True, check=False)  # noqa: S603
    if result.returncode not in (0, 1):
        print(result.stderr, file=sys.stderr)
        sys.exit(f"CLI failed: {' '.join(args)}")
    return result.stdout


def refresh_cookie(response: httpx.Response) -> str | None:
    match = re.search(rf"{COOKIE}=([^;]*)", response.headers.get("set-cookie", ""))
    return match.group(1) if match else None


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def main() -> None:
    run = secrets.token_hex(4)
    admin_email = f"smoke-admin-{run}@example.com"
    analyst_email = f"smoke-analyst-{run}@example.com"
    client = httpx.Client(base_url=BASE, headers=HEADERS, timeout=15)

    print(f"SentinelEdge auth smoke test against {BASE} (run {run})\n")
    print("Bootstrap")
    output = cli("create-admin", "--email", admin_email, "--name", "Smoke Admin")
    one_time = re.search(r"One-time password: (\S+)", output)
    check("create-admin issues a one-time password", one_time is not None)
    if one_time is None:  # for the type checker; check() has already exited
        return

    response = client.post(
        "/api/v1/auth/login", json={"email": admin_email, "password": one_time.group(1)}
    )
    token = response.json()["access_token"]
    check("admin signs in with the one-time password", response.status_code == 200)
    check(
        "refresh cookie is __Host-, HttpOnly, Secure, SameSite=Strict",
        all(
            a in response.headers["set-cookie"]
            for a in ("__Host-", "HttpOnly", "Secure", "SameSite=strict")
        ),
    )
    response = client.get("/api/v1/platform/capabilities", headers=bearer(token))
    check("all other access is blocked until setup is complete", response.status_code == 403)

    print("\nAccount setup")
    new_password = f"smoke test passphrase {run} orchard"
    response = client.post(
        "/api/v1/auth/password/change",
        headers=bearer(token),
        json={"current_password": one_time.group(1), "new_password": new_password},
    )
    check("admin replaces the one-time password", response.status_code == 204)
    secret = client.post("/api/v1/auth/mfa/enroll", headers=bearer(token)).json()["secret"]
    response = client.post(
        "/api/v1/auth/mfa/enroll/confirm",
        headers=bearer(token),
        json={"code": pyotp.TOTP(secret).now()},
    )
    check(
        "MFA enrolled with 10 recovery codes", len(response.json().get("recovery_codes", [])) == 10
    )
    check(
        "setup complete: protected endpoints now reachable",
        client.get("/api/v1/platform/capabilities", headers=bearer(token)).status_code == 200,
    )

    print("\nInvitation")
    response = client.post(
        "/api/v1/users",
        headers=bearer(token),
        json={"email": analyst_email, "display_name": "Smoke Analyst", "role": "ANALYST"},
    )
    check(
        "admin invites an analyst; response holds no secret",
        response.status_code == 201 and "token" not in response.text,
    )
    links = re.findall(r"#token=([A-Za-z0-9_-]+)", cli("outbox", "--limit", "50"))
    analyst_password = f"violet canyon river {run}"
    response = client.post(
        "/api/v1/auth/password/reset", json={"token": links[-1], "new_password": analyst_password}
    )
    check("analyst sets their own password from the outbox link", response.status_code == 204)
    response = client.post(
        "/api/v1/auth/login", json={"email": analyst_email, "password": analyst_password}
    )
    analyst_token, analyst_cookie = response.json()["access_token"], refresh_cookie(response)
    check("analyst signs in", response.status_code == 200)

    print("\nAuthorization")
    check(
        "analyst cannot list users (BFLA)",
        client.get("/api/v1/users", headers=bearer(analyst_token)).status_code == 403,
    )
    check(
        "analyst cannot read audit logs",
        client.get("/api/v1/audit-logs", headers=bearer(analyst_token)).status_code == 403,
    )
    admin_id = client.get("/api/v1/auth/me", headers=bearer(token)).json()["id"]
    check(
        "analyst cannot read another user's record (BOLA: 404)",
        client.get(f"/api/v1/users/{admin_id}", headers=bearer(analyst_token)).status_code == 404,
    )

    print("\nSessions")
    rotated = client.post("/api/v1/auth/refresh", headers={"Cookie": f"{COOKIE}={analyst_cookie}"})
    check(
        "refresh rotates the token",
        rotated.status_code == 200 and refresh_cookie(rotated) != analyst_cookie,
    )
    replay = client.post("/api/v1/auth/refresh", headers={"Cookie": f"{COOKIE}={analyst_cookie}"})
    check("replayed refresh token refused", replay.status_code == 401)
    check(
        "replay ends the whole session",
        client.get("/api/v1/auth/me", headers=bearer(rotated.json()["access_token"])).status_code
        == 401,
    )
    evil = httpx.post(
        f"{BASE}/api/v1/auth/login",
        json={"email": analyst_email, "password": analyst_password},
        headers={"Origin": "https://evil.example", "X-SentinelEdge-CSRF": "1"},
    )
    check("cross-site sign-in rejected (CSRF)", evil.status_code == 403)
    for _ in range(5):
        client.post(
            "/api/v1/auth/login", json={"email": analyst_email, "password": "not the password"}
        )
    response = client.post(
        "/api/v1/auth/login", json={"email": analyst_email, "password": analyst_password}
    )
    check("five failures lock the account", response.status_code == 401)

    print("\nMFA sign-in and audit")
    client.post("/api/v1/auth/logout", headers=bearer(token))
    check(
        "logout revokes the session",
        client.get("/api/v1/auth/me", headers=bearer(token)).status_code == 401,
    )
    response = client.post(
        "/api/v1/auth/login", json={"email": admin_email, "password": new_password}
    )
    check(
        "password alone yields only an MFA challenge",
        response.json().get("status") == "mfa_required",
    )
    code = pyotp.TOTP(secret).at(datetime.now(UTC) + timedelta(seconds=30))
    response = client.post(
        "/api/v1/auth/mfa/verify",
        json={"challenge_token": response.json()["challenge_token"], "code": code},
    )
    token = response.json()["access_token"]
    check("TOTP completes sign-in", response.status_code == 200)
    actions = {
        e["action"]
        for e in client.get(
            "/api/v1/audit-logs", headers=bearer(token), params={"limit": 100}
        ).json()["items"]
    }
    for action in (
        "auth.account_locked",
        "auth.refresh_token_reuse",
        "authz.denied",
        "user.created",
    ):
        check(f"audit log recorded {action}", action in actions)
    status = client.get("/api/v1/audit-logs/verify", headers=bearer(token)).json()
    check(f"audit chain intact ({status['records_checked']} records)", status["intact"])

    print("\nAPI security (Phase 6)")
    inventory = client.get("/api/v1/api-security/inventory", headers=bearer(token))
    items = inventory.json().get("items", []) if inventory.status_code == 200 else []
    check(f"admin reads the API inventory ({len(items)} endpoints)", len(items) >= 20)
    check(
        "every endpoint has authentication, authorization, risk and a rate limit",
        all(
            all(i[k] for k in ("authentication", "authorization", "risk", "rate_limit"))
            for i in items
        ),
    )
    check(
        "the inventory requires a session",
        client.get("/api/v1/api-security/inventory").status_code == 401,
    )
    # Exhaust the readiness probe's per-IP bucket (it refills within a minute and affects only
    # probes from this machine). The spoofed X-Forwarded-For must be ignored.
    spoofed = {"X-Forwarded-For": "6.6.6.6"}
    probes = [client.get("/api/v1/ready", headers=spoofed) for _ in range(125)]
    throttled = [r for r in probes if r.status_code == 429]
    check("probe flood is throttled with 429", len(throttled) > 0)
    check(
        "throttled response carries Retry-After and RateLimit headers",
        bool(throttled)
        and "retry-after" in throttled[0].headers
        and "ratelimit-limit" in throttled[0].headers,
    )
    entries = client.get(
        "/api/v1/audit-logs",
        headers=bearer(token),
        params={"action": "ratelimit.exceeded", "limit": 20},
    ).json()["items"]
    ready_entries = [e for e in entries if e["resource_id"] == "GET /api/v1/ready"]
    check("rate limiting is audited", bool(ready_entries))
    check(
        "spoofed X-Forwarded-For is ignored (real client IP recorded)",
        bool(ready_entries) and ready_entries[0]["source_ip"] != "6.6.6.6",
    )
    after = client.get("/api/v1/api-security/inventory", headers=bearer(token)).json()["items"]
    ready = next(i for i in after if i["method"] == "GET" and i["path"] == "/api/v1/ready")
    check("inventory counts the throttled probes", ready["metrics"]["throttled"] > 0)

    print(f"\nAll {passed} checks passed.")


if __name__ == "__main__":
    main()
