#!/usr/bin/env python3
"""End-to-end smoke test of authentication, authorization, auditing, API security and security
operations, run against the live local stack through the nginx edge exactly as a browser would.

    make smoke            # stack must be running (make dev)

Each run creates its own uniquely named admin and analyst (synthetic @example.com addresses) via
the API container's CLI, so it can be repeated. It deliberately locks the analyst account it
created, and exhausts this machine's readiness-probe rate limit, which refills within a minute.
It also runs two attack-simulator scenarios (synthetic, in memory, labelled simulated) and switches
the simulated WAF's SQL injection rules to count and back. Nothing else is modified.

All requests come from this one machine, so the smoke run's deliberate token replay, lockout and
injection probe fold into a single open live incident for this address. That is expected.

Note on cookies: browsers send `Secure` cookies to http://localhost; this HTTP client does not,
so the script carries the refresh cookie explicitly. That reproduces browser behaviour; it does
not relax anything on the server.
"""

from __future__ import annotations

import os
import re
import secrets
import subprocess
import sys
import uuid
from datetime import UTC, datetime, timedelta

import httpx2 as httpx
import pyotp

BASE = os.environ.get("SMOKE_BASE_URL", "http://localhost:8080")
# A fixed command, never taken from the environment: the smoke test runs with the caller's
# privileges, so an overridable command would be an injection point (Semgrep, Phase 8).
CLI = ("docker", "compose", "exec", "-T", "api", "python", "-m", "app.cli")
HEADERS = {"Origin": BASE, "X-SentinelEdge-CSRF": "1"}
COOKIE = "__Host-sentinel_refresh"
# RFC 5737 documentation ranges: the only addresses the attack simulator ever uses.
DOC_RANGES = ("192.0.2.", "198.51.100.", "203.0.113.")
# The probe policy allows a burst of 120 and refills 2 per second; 400 is far beyond what any
# working limiter needs, and well under the 600-per-minute global ceiling.
PROBE_BURST_CAP = 400

passed = 0


def check(label: str, condition: bool) -> None:
    global passed
    if not condition:
        print(f"  FAIL  {label}")
        sys.exit(1)
    passed += 1
    print(f"  PASS  {label}")


def cli(*args: str) -> str:
    # CLI is a constant and args come from this script, never from input or the environment.
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
    # probes from this machine). The bucket refills while the burst runs, so keep going until the
    # first 429 rather than sending a fixed number; the cap stops a broken limiter looping forever.
    # The spoofed X-Forwarded-For must be ignored.
    spoofed = {"X-Forwarded-For": "6.6.6.6"}
    throttled = []
    sent = 0
    while sent < PROBE_BURST_CAP and not throttled:
        sent += 1
        response = client.get("/api/v1/ready", headers=spoofed)
        if response.status_code == 429:
            throttled.append(response)
    check(f"probe flood is throttled with 429 (after {sent} requests)", len(throttled) > 0)
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

    security_operations(client, token)
    viewer = vulnerability_management(client, token, run)
    governance(client, token, viewer)

    print(f"\nAll {passed} checks passed.")


def security_operations(client: httpx.Client, token: str) -> None:
    """Phase 7: detection, the attack simulator and its WAF, the dashboard and provenance."""
    auth = bearer(token)

    def simulate_sql_injection() -> tuple[int, dict[str, int]]:
        response = client.post(
            "/api/v1/simulator/runs", headers=auth, json={"scenario": "sql_injection"}
        )
        if response.status_code != 201:
            return response.status_code, {}
        return 201, response.json().get("summary", {}).get("requests", {})

    def set_mode(rule: str, mode: str) -> int:
        url = f"/api/v1/simulator/waf-rules/{rule}"
        return client.put(url, headers=auth, json={"mode": mode}).status_code

    print("\nSecurity operations (Phase 7)")
    # A request carrying a SQL injection pattern is served (detect-only) and recorded as a LOCAL
    # event by the HTTP analysis rules.
    probe = {"q": "1' OR '1'='1' --"}
    response = client.get("/api/v1/platform/capabilities", headers=auth, params=probe)
    check(
        "a request carrying SQL injection is served (detection only)", response.status_code == 200
    )
    events = client.get(
        "/api/v1/security-events",
        headers=auth,
        params={"view": "live", "source": "http_analysis", "limit": 5},
    ).json()["items"]
    check(
        "HTTP analysis recorded it as a live event under a SQLI rule",
        any((e["rule_id"] or "").startswith("SQLI") and e["provenance"] == "LOCAL" for e in events),
    )

    scenarios = client.get("/api/v1/simulator/scenarios", headers=auth).json()["items"]
    check(f"the attack simulator lists its scenarios ({len(scenarios)})", len(scenarios) == 11)
    status_code, blocking = simulate_sql_injection()
    check("a SQL injection simulation runs", status_code == 201)
    check(
        "the simulated WAF blocks injections at the edge by default",
        blocking.get("blocked_by_waf", 0) > 0,
    )

    rules = client.get("/api/v1/simulator/waf-rules", headers=auth).json()["items"]
    sqli = [
        r["rule_id"] for r in rules if r["category"] == "sql_injection" and r["mode"] == "block"
    ]
    try:
        switched = [set_mode(rule, "count") for rule in sqli]
        check(
            f"SQL injection WAF rules switch to count mode ({len(sqli)} rules)",
            bool(sqli) and all(code == 200 for code in switched),
        )
        _, counting = simulate_sql_injection()
        check(
            "in count mode the requests reach the application and are detected there",
            counting.get("blocked_by_waf") == 0 and counting.get("reached_app", 0) > 0,
        )
    finally:
        # Always leave the simulated WAF as it was found, even when a check above fails.
        restored = [set_mode(rule, "block") for rule in sqli]
    check("the WAF rules are restored to block", all(code == 200 for code in restored))

    simulated = client.get(
        "/api/v1/security/overview", headers=auth, params={"view": "simulated", "hours": 24}
    ).json()
    check(
        "the simulated dashboard counts simulated events and simulator traffic",
        simulated["events"]["total"] > 0
        and simulated["traffic"]["source"] == "simulator"
        and simulated["traffic"]["requests"] > 0,
    )
    live = client.get(
        "/api/v1/security/overview", headers=auth, params={"view": "live", "hours": 24}
    ).json()
    check(
        "the live dashboard uses API metrics and no simulated addresses",
        live["traffic"]["source"] == "api_metrics"
        and not any(s["source_ip"].startswith(DOC_RANGES) for s in live["top_sources"]),
    )
    incidents = {
        view: client.get(
            "/api/v1/incidents", headers=auth, params={"view": view, "state": "all"}
        ).json()["items"]
        for view in ("simulated", "live")
    }
    check(
        "simulated incidents exist and are labelled simulated",
        bool(incidents["simulated"])
        and all(i["provenance"] in ("SIMULATED", "DEMO") for i in incidents["simulated"]),
    )
    check(
        "live incidents contain no simulated data",
        all(i["provenance"] in ("LOCAL", "REAL_AWS") for i in incidents["live"]),
    )
    apps = client.get("/api/v1/applications", headers=auth).json()["items"]
    check(
        "the application inventory lists the platform itself",
        any(a["slug"] == "sentineledge" and a["is_platform"] for a in apps),
    )
    chain = client.get("/api/v1/audit-logs/verify", headers=auth).json()
    check(
        f"audit chain intact after the simulations ({chain['records_checked']} records)",
        chain["intact"],
    )


def vulnerability_management(client: httpx.Client, token: str, run: str) -> dict[str, str]:
    """Phase 8: the findings, scan and SBOM endpoints answer and enforce their rules. Read-only:
    the smoke test never imports scans, so it leaves the local findings untouched."""
    auth = bearer(token)
    print("\nVulnerability management (Phase 8)")
    # The earlier analyst is locked out on purpose (Sessions); invite a read-only viewer.
    viewer_email = f"smoke-viewer-{run}@example.com"
    client.post(
        "/api/v1/users",
        headers=auth,
        json={"email": viewer_email, "display_name": "Smoke Viewer", "role": "VIEWER"},
    )
    links = re.findall(r"#token=([A-Za-z0-9_-]+)", cli("outbox", "--limit", "50"))
    viewer_password = f"amber meadow lantern {run}"
    client.post(
        "/api/v1/auth/password/reset", json={"token": links[-1], "new_password": viewer_password}
    )
    response = client.post(
        "/api/v1/auth/login", json={"email": viewer_email, "password": viewer_password}
    )
    check("a viewer is invited and signs in for these checks", response.status_code == 200)
    viewer = bearer(response.json().get("access_token", ""))
    overview = client.get("/api/v1/vulnerabilities/overview", headers=auth)
    check(
        "the vulnerability overview answers with counts",
        overview.status_code == 200 and isinstance(overview.json().get("active_total"), int),
    )
    listing = client.get("/api/v1/vulnerabilities", headers=viewer, params={"limit": 5})
    check("a viewer can read findings", listing.status_code == 200)
    missing = f"/api/v1/vulnerabilities/{uuid.uuid4()}"
    check("an unknown finding is not found", client.get(missing, headers=auth).status_code == 404)
    change = client.post(
        f"{missing}/status", headers=viewer, json={"status": "in_progress", "version": 1}
    )
    check("a viewer cannot change a finding's status (BFLA)", change.status_code == 403)
    check(
        "scans and SBOMs are listed",
        client.get("/api/v1/scans", headers=auth).status_code == 200
        and client.get("/api/v1/sboms", headers=auth).status_code == 200,
    )
    check(
        "findings require authentication",
        client.get("/api/v1/vulnerabilities").status_code == 401,
    )
    bogus = client.get("/api/v1/vulnerabilities", headers=auth, params={"min_severity": "bogus"})
    check("an invalid filter is rejected", bogus.status_code == 422)
    return viewer


def governance(client: httpx.Client, token: str, viewer: dict[str, str]) -> None:
    """Phase 10: the catalogue and SentinelEdge's own threat model are in the application and
    read-only there; the posture score explains itself; nobody approves their own exception or
    change. Each run leaves one withdrawn exception and one cancelled change request."""
    auth = bearer(token)
    print("\nThreat modeling and governance (Phase 10)")
    controls = client.get("/api/v1/governance/controls", headers=viewer).json()
    check(
        "the control catalogue is loaded from the reviewed documents",
        len(controls.get("items", [])) >= 90 and controls["counts"]["implemented"] > 0,
    )
    models = client.get("/api/v1/threat-models", headers=auth).json().get("items", [])
    own = next((m for m in models if m["origin"] == "catalogue"), None)
    check("SentinelEdge's own threat model is in the application", own is not None)
    if own is not None:
        edit = client.patch(
            f"/api/v1/threat-models/{own['id']}",
            headers=auth,
            json={"version": own["version"], "name": "Edited in the UI"},
        )
        check(
            "SentinelEdge's own threat model is read-only (maintained as code)",
            edit.status_code == 409 and edit.json()["error"]["code"] == "maintained_as_code",
        )
    posture = client.get("/api/v1/governance/posture", headers=viewer).json()
    check(
        "the posture score explains every category",
        len(posture.get("categories", [])) == 11
        and all(c["factors"] for c in posture["categories"]),
    )
    expires = (datetime.now(UTC).date() + timedelta(days=20)).isoformat()
    exception = client.post(
        "/api/v1/exceptions",
        headers=auth,
        json={
            "title": "Smoke test exception (withdrawn immediately)",
            "scope": "other",
            "scope_ref": "smoke test",
            "risk_level": "low",
            "risk": "None: created by the smoke test to exercise the workflow.",
            "justification": "Exercises separation of duties on every smoke run.",
            "compensating_control": "Withdrawn immediately by the same smoke run.",
            "expires_on": expires,
        },
    ).json()
    own_decision = client.post(
        f"/api/v1/exceptions/{exception.get('id')}/decision",
        headers=auth,
        json={"approve": True, "version": 1},
    )
    check(
        "an exception cannot be approved by its requester (separation of duties)",
        own_decision.status_code == 409
        and own_decision.json()["error"]["code"] == "separation_of_duties",
    )
    withdrawn = client.post(
        f"/api/v1/exceptions/{exception.get('id')}/close",
        headers=auth,
        json={"note": "Smoke test: withdrawn.", "version": 1},
    )
    check(
        "the request is withdrawn with a reason",
        withdrawn.status_code == 200 and withdrawn.json()["status"] == "withdrawn",
    )
    denied = client.post("/api/v1/exceptions", headers=viewer, json={})
    check("a viewer cannot request an exception", denied.status_code == 403)
    change = client.post(
        "/api/v1/change-requests",
        headers=auth,
        json={
            "title": "Smoke test change (cancelled immediately)",
            "change_type": "waf_rule",
            "description": "Count SQLI-001 in the simulated WAF; never approved.",
            "risk_level": "low",
            "impact": "None: cancelled by the same smoke run before any decision.",
            "rollback_plan": "Nothing to roll back: it is never implemented.",
            "validation_plan": "None needed: it is cancelled immediately.",
            "target": {"rule_id": "SQLI-001", "mode": "count"},
        },
    ).json()
    url = f"/api/v1/change-requests/{change.get('id')}/transition"
    own_approval = client.post(url, headers=auth, json={"to": "approved", "version": 1})
    cancelled = client.post(
        url, headers=auth, json={"to": "cancelled", "note": "Smoke test: cancelled.", "version": 1}
    )
    check(
        "a change request cannot be approved by its requester, and is cancelled",
        own_approval.status_code == 409
        and cancelled.status_code == 200
        and cancelled.json()["status"] == "cancelled",
    )


if __name__ == "__main__":
    main()
