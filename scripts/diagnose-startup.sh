#!/usr/bin/env bash
# Explain a failed `make dev` in plain words. Run automatically by `make dev` when
# `docker compose up` fails; safe to run by hand. Reads container state and logs only.
set -uo pipefail

migrate_logs="$(docker compose logs --no-color migrate 2>/dev/null | tail -n 60)"
db_logs="$(docker compose logs --no-color db 2>/dev/null | tail -n 60)"

echo
echo "Startup diagnosis"
echo "-----------------"

if grep -qE 'password authentication failed for user "sentinel_(migrator|app)"|role "sentinel_(migrator|app)" does not exist' <<<"$migrate_logs"; then
  cat <<'EOF'
The database volume was created with different credentials than your current .env.
PostgreSQL creates the SentinelEdge roles only when its volume is first initialised, so
a volume from an earlier .env (or an earlier phase) keeps the old passwords.

Fix (deletes the LOCAL database only; keep your current .env):
  docker compose down -v
  make dev
EOF
  exit 0
fi

if grep -q "Refusing to bootstrap" <<<"$db_logs"; then
  cat <<'EOF'
The database bootstrap refused to run as the application role: your .env predates Phase 2.

Fix (deletes the LOCAL database only):
  make clean && mv .env .env.bak && make env && make dev
EOF
  exit 0
fi

if grep -qiE 'could not translate host name|connection refused|timeout expired' <<<"$migrate_logs"; then
  echo "The migrate container could not reach the database. Check it is healthy:"
  echo "  docker compose ps -a"
  echo "  docker compose logs db | tail -30"
  exit 0
fi

echo "No known cause matched. The last lines from the migrate and db containers:"
echo
echo "== migrate =="
tail -n 15 <<<"$migrate_logs"
echo
echo "== db =="
tail -n 15 <<<"$db_logs"
