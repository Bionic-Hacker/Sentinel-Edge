#!/usr/bin/env bash
# make edge-check: run scripts/edge-check.py against the deployed edge, with the names taken from
# the dev stack's outputs (read through scripts/tf.sh: right account, never root).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
read -r url alb cloudfront < <("$ROOT/scripts/tf.sh" dev output-json | python3 -c '
import json, sys
w = (json.load(sys.stdin).get("workload") or {}).get("value")
if not w:
    sys.exit("edge-check: the workload is off: there is no edge to check")
print(w["url"], w["alb_dns_name"], w["distribution_dns"])
')
[[ -n "${url:-}" ]] || { echo "edge-check: could not read the dev stack's outputs" >&2; exit 1; }
exec python3 "$ROOT/scripts/edge-check.py" --url "$url" --alb "$alb" --cloudfront "$cloudfront"
