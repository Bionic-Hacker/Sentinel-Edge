# syntax=docker/dockerfile:1.7
# SentinelEdge dbadmin image: creates the application's database roles and schema on RDS, once
# per deploy window, as the ECS task "dbadmin" (Phase 4, ADR-0026). It runs exactly the script
# used locally and in CI, with libpq's PG* variables and verified TLS (sslmode verify-full).
#
# Build (scripts/images-push.sh does this):
#   docker build -f db/Dockerfile --build-context certs=backend/certs db
#
# The PostgreSQL image is used only for its client; no server runs in this container.

# checkov:skip=CKV_DOCKER_2: a one-off task that runs a script and exits; it serves nothing a health check could probe, and ECS judges it by its exit code
FROM postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24
COPY --chown=root:root --chmod=0755 bootstrap-roles.sh /usr/local/bin/bootstrap-roles.sh
COPY --from=certs --chown=root:root rds-global-bundle.pem /srv/certs/rds-global-bundle.pem
# The image's own unprivileged postgres user (UID 70); the task also runs it read-only.
USER 70:70
ENTRYPOINT ["/usr/local/bin/bootstrap-roles.sh"]
