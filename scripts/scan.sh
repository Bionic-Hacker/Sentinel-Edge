#!/usr/bin/env bash
# SentinelEdge application security scans (Phase 8, ADR-0020).
#
#   scripts/scan.sh [sast] [sca] [secrets] [iac] [container] [sbom] [dast] [gate]
#
# With no arguments every scan except dast runs, then the gate. Each scanner writes JSON to
# reports/scan/; the gate (backend/app/scanning/gate.py) reduces them to one list of findings and
# fails on any critical or high finding that is fixable and not covered by an accepted risk.
#
# Every scanner runs in a pinned container image, as the calling user, with the repository
# mounted read-only. No scanner gets the Docker socket: images are scanned from `docker save`
# tarballs. DAST needs the local stack running (`make dev`) and only ever targets it.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/reports/scan"
CACHE="$ROOT/reports/cache"
cd "$ROOT"

# Scanner images: pinned by version tag and digest (`make image-digests` finds stale pins).
# Override only to test an upgrade.
SEMGREP_IMAGE="${SEMGREP_IMAGE:-semgrep/semgrep:1.180.0@sha256:529ee8a277ec8adc5b534d7c74eea0a47e9de21d62852b6ba7ac6ba9566845c3}"
TRIVY_IMAGE="${TRIVY_IMAGE:-aquasec/trivy:0.75.0@sha256:af6acf9a6b85dfe389a1941505c0ce9efef52a4719635e1a962f022a3d855daa}"
CHECKOV_IMAGE="${CHECKOV_IMAGE:-bridgecrew/checkov:3.3.26@sha256:8e63f217cb084f1c1a067326a9cf6e37d54bdc82e5822210d50ca4e2f647dd93}"
SYFT_IMAGE="${SYFT_IMAGE:-anchore/syft:v1.54.1@sha256:3eb5379ba7b409c3f4069b686110527af0c47df993fa5c10d13e7cf34f49b1aa}"
GITLEAKS_IMAGE="${GITLEAKS_IMAGE:-ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f}"
ZAP_IMAGE="${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:2.17.0@sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef}"

# Semgrep registry rulesets (fetched from semgrep.dev). SEMGREP_RULESETS="" runs only the
# SentinelEdge rules, for offline use; CI always uses the full set.
SEMGREP_RULESETS="${SEMGREP_RULESETS-p/python p/typescript p/react}"

# The local stack's web entry point. DAST refuses any other target.
DAST_TARGET="http://localhost:8080"
API_IMAGE="sentineledge-api:scan"
WEB_IMAGE="sentineledge-web:scan"

USER_FLAGS=(-u "$(id -u):$(id -g)" -e HOME=/tmp)
SRC=(-v "$ROOT:/src:ro")
OUTV=(-v "$OUT:/out")

log() { printf '\n==> %s\n' "$*"; }

# A tool from the backend's tooling (make install): backend/.venv, then .venv, then PATH.
tool() {
  local t
  for t in "$ROOT/backend/.venv/bin/$1" "$ROOT/.venv/bin/$1"; do
    [[ -x "$t" ]] && { echo "$t"; return; }
  done
  command -v "$1" || { echo "scan: $1 not found; run \`make install\` first" >&2; exit 2; }
}

sast() {
  log "SAST: Semgrep (${SEMGREP_RULESETS:-no registry rulesets} + SentinelEdge rules)"
  local rulesets=()
  for r in $SEMGREP_RULESETS; do rulesets+=(--config "$r"); done
  docker run --rm "${USER_FLAGS[@]}" "${SRC[@]}" "${OUTV[@]}" -w /src \
    -e SEMGREP_SEND_METRICS=off "$SEMGREP_IMAGE" \
    semgrep scan --metrics=off --disable-version-check --quiet \
      "${rulesets[@]}" --config /src/scanning/semgrep \
      --exclude scanning/semgrep --exclude node_modules --exclude .venv --exclude reports \
      --json --output /out/semgrep.json /src
  log "SAST: Bandit"
  local bandit
  bandit="$(tool bandit)"
  # Bandit exits 1 when it finds anything; the gate decides, so only a missing report fails.
  (cd backend && "$bandit" -q -c pyproject.toml -r app -f json -o "$OUT/bandit.json") || true
  test -s "$OUT/bandit.json" || { echo "Bandit wrote no report" >&2; exit 2; }
}

sca() {
  log "SCA: Trivy (Python and npm lock files)"
  docker run --rm "${USER_FLAGS[@]}" "${SRC[@]}" "${OUTV[@]}" -v "$CACHE/trivy:/cache" \
    "$TRIVY_IMAGE" fs --cache-dir /cache --scanners vuln --quiet \
      --skip-dirs '**/node_modules' --skip-dirs '**/.venv' --skip-dirs reports \
      --format json --output /out/trivy-fs.json /src
}

secrets() {
  log "Secrets: Gitleaks (working tree and full history)"
  docker run --rm "${USER_FLAGS[@]}" "${SRC[@]}" "${OUTV[@]}" "$GITLEAKS_IMAGE" \
    git /src --config /src/.gitleaks.toml --redact --no-banner \
      --report-format json --report-path /out/gitleaks.json --exit-code 0
}

iac() {
  log "IaC and configuration: Checkov"
  docker run --rm "${USER_FLAGS[@]}" "${SRC[@]}" -w /src "$CHECKOV_IMAGE" \
    --config-file /src/scanning/checkov.yaml --soft-fail -o json > "$OUT/checkov.json"
}

build_images() {
  if [[ ! -f "$CACHE/api.tar" || ! -f "$CACHE/web.tar" || "${REBUILD:-1}" == 1 ]]; then
    log "Building the API and web images"
    docker build -q -t "$API_IMAGE" backend >/dev/null
    docker build -q -t "$WEB_IMAGE" frontend >/dev/null
    docker save -o "$CACHE/api.tar" "$API_IMAGE"
    docker save -o "$CACHE/web.tar" "$WEB_IMAGE"
    REBUILD=0
  fi
}

container() {
  build_images
  for name in api web; do
    log "Container: Trivy ($name image: OS packages, libraries, misconfiguration)"
    docker run --rm "${USER_FLAGS[@]}" -v "$CACHE:/cache" "${OUTV[@]}" "$TRIVY_IMAGE" \
      image --cache-dir /cache/trivy --quiet --scanners vuln,misconfig,secret \
        --input "/cache/$name.tar" --format json --output "/out/trivy-image-$name.json"
  done
}

sbom() {
  build_images
  # Syft's image is FROM scratch and its /tmp is not writable by an unprivileged user; it
  # unpacks image layers there, so give it a scratch directory of our own.
  local SYFT_TMP="$CACHE/syft-tmp"
  local SYFT_ENV=(-e SYFT_CHECK_FOR_APP_UPDATE=false)
  rm -rf "$SYFT_TMP" && mkdir -p "$SYFT_TMP"
  for name in api web; do
    log "SBOM: Syft ($name image, CycloneDX)"
    docker run --rm "${USER_FLAGS[@]}" "${SYFT_ENV[@]}" -v "$CACHE:/cache:ro" "${OUTV[@]}" \
      -v "$SYFT_TMP:/tmp" "$SYFT_IMAGE" \
      scan "docker-archive:/cache/$name.tar" -o "cyclonedx-json=/out/sbom-$name.cdx.json"
  done
  log "SBOM: Syft (source tree, CycloneDX)"
  docker run --rm "${USER_FLAGS[@]}" "${SYFT_ENV[@]}" "${SRC[@]}" "${OUTV[@]}" \
    -v "$SYFT_TMP:/tmp" "$SYFT_IMAGE" \
    scan dir:/src --exclude './frontend/node_modules' --exclude './backend/.venv' --exclude './.venv' \
      --exclude './reports' -o "cyclonedx-json=/out/sbom-source.cdx.json"
  rm -rf "$SYFT_TMP"
}

dast() {
  log "DAST: ZAP baseline (passive) against $DAST_TARGET"
  if ! curl -fsS -o /dev/null "$DAST_TARGET/"; then
    echo "The local stack is not answering on $DAST_TARGET; run \`make dev\` first." >&2
    exit 2
  fi
  local work
  work="$(mktemp -d)"
  chmod 0777 "$work"  # ZAP writes as its own user (zap, UID 1000); nothing secret goes here
  # -I: warnings never fail this step; the gate decides. Host networking so ZAP reaches the
  # stack on localhost, the only origin the web container trusts.
  docker run --rm --network host -v "$work:/zap/wrk:rw" "$ZAP_IMAGE" \
    zap-baseline.py -t "$DAST_TARGET" -J zap-baseline.json -I -m 2 || true
  test -s "$work/zap-baseline.json" || { echo "ZAP wrote no baseline report" >&2; exit 2; }
  cp "$work/zap-baseline.json" "$OUT/zap-baseline.json"

  log "DAST: ZAP API scan (active, authenticated as the read-only DAST scanner)"
  # The OpenAPI document pinned to the local stack, without the logout endpoint.
  docker compose exec -T api python -m app.cli openapi --server "$DAST_TARGET" > "$work/openapi.json"
  # A session for the VIEWER-only scanner account: it reads what a viewer may and every write
  # it attempts is refused. The token goes to a mode-600 env file, never onto a command line,
  # and the session is revoked when this step ends, however it ends.
  local token
  DAST_SECRETS="$(mktemp -d)"
  trap revoke_dast EXIT
  token="$(docker compose exec -T api python -m app.cli dast-session issue)"
  [[ "$token" =~ ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$ ]] \
    || { echo "Could not issue the DAST scanner session" >&2; exit 2; }
  (umask 077 && printf 'ZAP_AUTH_HEADER=Authorization\nZAP_AUTH_HEADER_VALUE=Bearer %s\nZAP_AUTH_HEADER_SITE=localhost\n' \
    "$token" > "$DAST_SECRETS/zap.env")
  unset token
  # -T: at most 20 minutes. Attack payloads reach only the local stack; HTTP analysis detects
  # them like any other attack, so expect live injection events for this machine's address.
  docker run --rm --network host --env-file "$DAST_SECRETS/zap.env" -v "$work:/zap/wrk:rw" "$ZAP_IMAGE" \
    zap-api-scan.py -t /zap/wrk/openapi.json -f openapi -J zap-api.json -I -T 20 || true
  test -s "$work/zap-api.json" || { echo "ZAP wrote no API scan report" >&2; exit 2; }
  cp "$work/zap-api.json" "$OUT/zap-api.json"
  rm -rf "$work"
  revoke_dast
}

DAST_SECRETS=""
revoke_dast() {
  [[ -n "$DAST_SECRETS" ]] || return 0
  docker compose exec -T api python -m app.cli dast-session revoke >/dev/null 2>&1 || true
  rm -rf "$DAST_SECRETS"
  DAST_SECRETS=""
}

gate() {
  log "Gate"
  local py
  py="$(tool python)"
  # Every scanner's report must be present: one that failed must not let the others pass.
  local expect=(semgrep bandit trivy-fs gitleaks checkov trivy-image-api trivy-image-web)
  [[ " ${steps[*]} " == *" dast "* ]] && expect+=(zap-baseline zap-api)
  local flags=()
  for name in "${expect[@]}"; do flags+=(--expect "$name.json"); done
  (cd backend && "$py" -m app.scanning.gate "$OUT" --root "$ROOT" "${flags[@]}" \
     --accepted "$ROOT/scanning/accepted-findings.toml" --json "$OUT/findings.json")
}

steps=("$@")
[[ ${#steps[@]} -eq 0 ]] && steps=(sast sca secrets iac container sbom gate)

# A full run starts from an empty report directory, so a stale report can never pass the gate.
if [[ " ${steps[*]} " == *" sast "* && " ${steps[*]} " == *" gate "* ]]; then
  rm -rf "$OUT"
fi
mkdir -p "$OUT" "$CACHE/trivy"

for step in "${steps[@]}"; do
  case "$step" in
    sast | sca | secrets | iac | container | sbom | dast | gate) "$step" ;;
    *) echo "unknown step: $step (sast sca secrets iac container sbom dast gate)" >&2; exit 2 ;;
  esac
done
