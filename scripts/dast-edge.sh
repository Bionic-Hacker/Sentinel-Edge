#!/usr/bin/env bash
# DAST against the live edge (Phase 12, C-CICD-12): a passive ZAP baseline of the deployed
# platform, through CloudFront and WAF, during a deploy window. Then the scan gate decides.
#
#   make dast-edge
#
# Passive only: ZAP spiders the site and reads what it is served; it sends no attack payloads,
# so nothing here depends on WAF letting an attack through. The target is read from the dev
# stack's outputs: it can only ever be the platform's own name.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ZAP_IMAGE="$(sed -nE 's/^ZAP_IMAGE="\$\{ZAP_IMAGE:-(.*)\}"$/\1/p' "$ROOT/scripts/scan.sh")"
OUT="$ROOT/reports/edge"

die() { printf 'dast-edge: %s\n' "$*" >&2; exit 2; }
outputs="$("$ROOT/scripts/tf.sh" dev output-json)" \
  || die "could not read the dev stack: sign in first (aws login --profile sentineledge)"
url="$(printf '%s' "$outputs" | python3 -c '
import json, sys
try:
    w = (json.load(sys.stdin).get("workload") or {}).get("value")
except json.JSONDecodeError:
    sys.exit("dast-edge: the dev stack returned no outputs: sign in, then run make tf-init STACK=dev")
sys.exit("dast-edge: the workload is off: open a deploy window first") if not w else print(w["url"])
')" || exit 2
[[ "$url" =~ ^https://[a-z0-9.-]+$ ]] || { echo "dast-edge: unexpected target $url" >&2; exit 2; }

mkdir -p "$OUT"
work="$(mktemp -d)"
chmod 0777 "$work" # ZAP writes as its own user; nothing secret goes here
echo "==> ZAP baseline (passive) against $url"
docker run --rm -v "$work:/zap/wrk:rw" "$ZAP_IMAGE" \
  zap-baseline.py -t "$url" -J zap-edge.json -I -m 3 || true
test -s "$work/zap-edge.json" || { echo "dast-edge: ZAP wrote no report" >&2; exit 2; }
cp "$work/zap-edge.json" "$OUT/zap-edge.json"
rm -rf "$work"

echo "==> Scan gate on the live-edge report"
py="$ROOT/.venv/bin/python"
[[ -x "$py" ]] || py=python3
cd "$ROOT/backend"
exec "$py" -m app.scanning.gate "$OUT" --root "$ROOT" --expect zap-edge.json \
  --accepted "$ROOT/scanning/accepted-findings.toml" --json "$OUT/findings.json"
