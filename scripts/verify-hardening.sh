#!/usr/bin/env bash
# Verify the running local stack's container and network hardening.
# Each check prints PASS or FAIL with the control it evidences; exit status is non-zero if any
# check fails. Run with the stack up: `make dev && make verify-hardening`.
set -uo pipefail

API_URL="${API_URL:-http://localhost:8000}"
WEB_URL="${WEB_URL:-http://localhost:8080}"
failures=0

pass() { printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; failures=$((failures + 1)); }
check() { # check "<description>" <command...>
  local description="$1"; shift
  if "$@" >/dev/null 2>&1; then pass "$description"; else fail "$description"; fi
}

container_id() { docker compose ps -q "$1"; }

for svc in api web db; do
  if [[ -z "$(container_id "$svc")" ]]; then
    echo "Service '$svc' is not running. Start the stack with: make dev" >&2
    exit 2
  fi
done

# Right after `make dev` the API may still be starting; HTTP checks need it to answer. Wait up
# to 60 seconds, and stop if it never does (a check must never pass on a missing response).
# Checks use GET: the API answers HEAD on its GET routes with 405.
for _ in $(seq 1 60); do
  curl -fsS -o /dev/null "$API_URL/api/v1/health" && break
  sleep 1
done
if ! curl -fsS -o /dev/null "$API_URL/api/v1/health"; then
  echo "The API is not answering on $API_URL after 60 seconds; see: make logs" >&2
  exit 2
fi

echo "Containers (C-CNT-01)"
for svc in api web; do
  check "$svc runs as a non-root user" \
    bash -c "[[ \$(docker compose exec -T $svc id -u) != 0 ]]"
  check "$svc root filesystem is read-only" \
    bash -c "! docker compose exec -T $svc touch /hardening-probe"
  check "$svc has no effective Linux capabilities" \
    bash -c "docker compose exec -T $svc grep -q '^CapEff:[[:space:]]*0000000000000000$' /proc/1/status"
done
for svc in api web db; do
  check "$svc has no-new-privileges set" \
    bash -c "docker inspect -f '{{json .HostConfig.SecurityOpt}}' $(container_id "$svc") | grep -q 'no-new-privileges:true'"
done

echo "Network (C-NET-00, T-DB-01)"
# Read the container's actual port bindings rather than `docker compose port`, whose exit status
# for an unpublished port differs between Compose releases (Compose v5 reports success).
check "database port is not published to the host" \
  bash -c "! docker inspect -f '{{json .NetworkSettings.Ports}}' $(container_id db) | grep -q HostPort"
check "database network is internal (no route out)" \
  bash -c "[[ \$(docker network inspect -f '{{.Internal}}' sentineledge_data) == true ]]"
check "API is bound to localhost only" \
  bash -c "docker compose port api 8000 | grep -q '^127.0.0.1:'"
check "web is bound to localhost only" \
  bash -c "docker compose port web 8080 | grep -q '^127.0.0.1:'"

echo "HTTP (C-API-07, C-WEB-01, C-WEB-02)"
check "forged Host header is rejected with 400" \
  bash -c "[[ \$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: evil.example' $API_URL/api/v1/health) == 400 ]]"
check "API sends a deny-all Content-Security-Policy" \
  bash -c "curl -sI $API_URL/api/v1/health | grep -qi \"^content-security-policy: default-src 'none'\""
check "SPA sends a strict CSP without unsafe-inline" \
  bash -c "curl -sI $WEB_URL/ | grep -i '^content-security-policy:' | grep -qv 'unsafe-inline'"
check "SPA is cross-origin isolated (COOP same-origin, COEP require-corp)" \
  bash -c "headers=\$(curl -fsS -D - -o /dev/null $WEB_URL/) && grep -qi '^cross-origin-opener-policy: same-origin' <<<\"\$headers\" && grep -qi '^cross-origin-embedder-policy: require-corp' <<<\"\$headers\""
check "API does not disclose a Server header" \
  bash -c "headers=\$(curl -fsS -D - -o /dev/null $API_URL/api/v1/health) && ! grep -qi '^server:' <<<\"\$headers\""

echo
if (( failures == 0 )); then
  echo "All hardening checks passed."
else
  echo "$failures hardening check(s) failed."
fi
exit $(( failures > 0 ))
