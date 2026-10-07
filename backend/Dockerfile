# syntax=docker/dockerfile:1.7
# SentinelEdge API image.
# - Multi-stage: build tooling never reaches the runtime image.
# - Hash-pinned dependencies (pip --require-hashes).
# - Non-root UID, no shell needed at runtime, read-only root FS compatible.
# Base image digest pinning + Trivy scanning are added in Phase 8 (container security gate).

ARG PYTHON_IMAGE=python:3.12-slim-bookworm

FROM ${PYTHON_IMAGE} AS builder
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY requirements.lock .
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --require-hashes --no-deps -r requirements.lock

FROM ${PYTHON_IMAGE} AS runtime
ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
RUN groupadd --system --gid 10001 sentinel \
 && useradd --system --uid 10001 --gid sentinel --no-create-home --shell /usr/sbin/nologin sentinel
COPY --from=builder /opt/venv /opt/venv
WORKDIR /srv
COPY --chown=root:root app ./app
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health', timeout=2).status == 200 else 1)"]
# --no-server-header: don't advertise uvicorn. --proxy-headers stays OFF until Phase 4,
# when forwarded-for trust is restricted to the ALB (see ADR-0001).
CMD ["uvicorn", "--factory", "app.main:create_app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header", "--no-access-log"]
