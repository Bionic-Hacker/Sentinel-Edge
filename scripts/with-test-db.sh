#!/usr/bin/env bash
# Run a command against a throwaway PostgreSQL prepared exactly like the real one.
#
#   scripts/with-test-db.sh python -m pytest
#
# - Same image as the dev stack, bootstrapped by the same db/bootstrap-roles.sh (ADR-0015).
# - Bound to 127.0.0.1 on a random free port; data lives in tmpfs and vanishes on exit.
# - Fresh random passwords every run; nothing is written to disk.
# - The container is removed on exit, whether the command passes, fails, or is interrupted.
set -euo pipefail

IMAGE="${TEST_DB_IMAGE:-postgres:17-alpine}"
NAME="sentineledge-testdb-$$"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rand() { openssl rand -hex 24; }

admin_password="$(rand)"
SENTINEL_DB_MIGRATOR_PASSWORD="$(rand)"
SENTINEL_DB_PASSWORD="$(rand)"
export SENTINEL_DB_MIGRATOR_PASSWORD SENTINEL_DB_PASSWORD

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM

docker run -d --rm --name "$NAME" \
  -p 127.0.0.1::5432 \
  --tmpfs /var/lib/postgresql/data \
  -e POSTGRES_DB=sentineledge_test \
  -e POSTGRES_USER=sentinel_admin \
  -e POSTGRES_PASSWORD="$admin_password" \
  -e SENTINEL_DB_MIGRATOR_PASSWORD \
  -e SENTINEL_DB_APP_PASSWORD="$SENTINEL_DB_PASSWORD" \
  -v "$ROOT/db/bootstrap-roles.sh:/docker-entrypoint-initdb.d/10-bootstrap-roles.sh:ro" \
  "$IMAGE" >/dev/null

# TCP readiness only becomes true after initialisation (including the role bootstrap) finishes.
for _ in $(seq 1 60); do
  if docker exec "$NAME" pg_isready -q -h 127.0.0.1 -U sentinel_admin -d sentineledge_test; then
    break
  fi
  sleep 1
done
docker exec "$NAME" pg_isready -q -h 127.0.0.1 -U sentinel_admin -d sentineledge_test || {
  echo "Test database did not become ready; container log follows:" >&2
  docker logs "$NAME" >&2
  exit 1
}

port="$(docker port "$NAME" 5432/tcp | head -n1 | sed 's/.*://')"
export SENTINEL_DB_HOST=127.0.0.1 SENTINEL_DB_PORT="$port" SENTINEL_DB_NAME=sentineledge_test
export SENTINEL_REQUIRE_DB=1

"$@"
