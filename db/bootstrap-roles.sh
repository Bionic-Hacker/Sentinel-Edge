#!/usr/bin/env bash
# Create SentinelEdge's database roles and schema (ADR-0015). Idempotent: safe to re-run, and
# re-running rotates both role passwords to the values supplied.
#
# Used in three places, so the database privilege model is identical everywhere:
#   - docker-compose: mounted into /docker-entrypoint-initdb.d, runs on first start of `db`
#   - CI and local tests: run against a throwaway PostgreSQL
#   - AWS (Phase 4): run once per deploy window against RDS, as the dbadmin task with the RDS
#     master credentials. That master is not a superuser, which the role attributes and the
#     schema hand-over below allow for.
#
# Connection uses standard libpq variables (PGHOST, PGPORT, PGUSER, PGDATABASE, PGPASSWORD).
# Inside the postgres image's init phase, PGUSER/PGDATABASE fall back to POSTGRES_USER/POSTGRES_DB.
#
# Roles:
#   sentinel_migrator  owns the `sentinel` schema; runs Alembic; never used by the running API
#   sentinel_app       runtime role; only the per-table grants each migration gives it
set -euo pipefail

: "${SENTINEL_DB_MIGRATOR_PASSWORD:?SENTINEL_DB_MIGRATOR_PASSWORD must be set}"
: "${SENTINEL_DB_APP_PASSWORD:?SENTINEL_DB_APP_PASSWORD must be set}"
export PGUSER="${PGUSER:-${POSTGRES_USER:-postgres}}"
export PGDATABASE="${PGDATABASE:-${POSTGRES_DB:-postgres}}"

# The bootstrap identity must be a separate administrative role. If it were one of the roles
# this script restricts, the script would strip its own privileges mid-run.
case "$PGUSER" in
  sentinel_app | sentinel_migrator)
    echo "Refusing to bootstrap as '$PGUSER': use a separate admin role (e.g. sentinel_admin)." >&2
    echo "If your .env predates Phase 2, regenerate it: see docs/local-development.md." >&2
    exit 1
    ;;
esac

psql --no-psqlrc --quiet -v ON_ERROR_STOP=1 \
  -v migrator_password="$SENTINEL_DB_MIGRATOR_PASSWORD" \
  -v app_password="$SENTINEL_DB_APP_PASSWORD" \
  -v dbname="$PGDATABASE" <<'SQL'
-- Roles: login only, no superuser, no role/database creation, no RLS bypass, no replication.
SELECT 'CREATE ROLE sentinel_migrator'
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_migrator') \gexec
SELECT 'CREATE ROLE sentinel_app'
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_app') \gexec

ALTER ROLE sentinel_migrator WITH LOGIN NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD :'migrator_password';
ALTER ROLE sentinel_app WITH LOGIN NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD :'app_password';

-- SUPERUSER, REPLICATION and BYPASSRLS can be changed only by a role that has them. A superuser
-- (local, CI) clears them explicitly. RDS's master is not a superuser and could never have set
-- them, so there they are checked instead, and the run fails if either role has any of them.
SELECT format('ALTER ROLE %I WITH NOSUPERUSER NOREPLICATION NOBYPASSRLS', r)
  FROM unnest(ARRAY['sentinel_migrator', 'sentinel_app']) AS r
 WHERE (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) \gexec
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles
              WHERE rolname IN ('sentinel_migrator', 'sentinel_app')
                AND (rolsuper OR rolreplication OR rolbypassrls)) THEN
    RAISE EXCEPTION 'an application role has SUPERUSER, REPLICATION or BYPASSRLS';
  END IF;
END
$$;

-- Handing the schema to sentinel_migrator needs the right to SET ROLE to it. A superuser has it
-- already; RDS's master (PostgreSQL 16 and later) needs the membership granted, without
-- inheriting the role's privileges.
SELECT format('GRANT sentinel_migrator TO %I WITH INHERIT FALSE, SET TRUE', current_user)
 WHERE NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) \gexec

-- Only these two roles may connect to the application database.
REVOKE ALL ON DATABASE :"dbname" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"dbname" TO sentinel_migrator, sentinel_app;

-- Nobody creates objects in `public`; the application lives in its own schema.
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA IF NOT EXISTS sentinel AUTHORIZATION sentinel_migrator;
ALTER SCHEMA sentinel OWNER TO sentinel_migrator;
-- Grants on the schema are made by its owner (a non-superuser master has no rights on it).
SET ROLE sentinel_migrator;
REVOKE ALL ON SCHEMA sentinel FROM PUBLIC;
GRANT USAGE ON SCHEMA sentinel TO sentinel_app;
RESET ROLE;

-- Per-database role settings.
ALTER ROLE sentinel_migrator IN DATABASE :"dbname" SET search_path = sentinel;
ALTER ROLE sentinel_app IN DATABASE :"dbname" SET search_path = sentinel;
-- Bound runaway or abusive queries from the API (resource-consumption defense, T-API-04).
ALTER ROLE sentinel_app IN DATABASE :"dbname" SET statement_timeout = '15s';
ALTER ROLE sentinel_app IN DATABASE :"dbname" SET idle_in_transaction_session_timeout = '30s';
SQL

echo "SentinelEdge database roles and schema are in place for database '$PGDATABASE'."
