#!/usr/bin/env bash
# Build the SPA and publish it to the edge's private bucket (make spa-push; Phase 5, ADR-0027).
#
# - Built from a clean, committed tree with the locked dependencies (npm ci, no install scripts).
# - Hashed assets are cached for a year (immutable); everything else, index.html above all, is
#   revalidated on every visit (no-cache), as nginx does locally.
# - Files the new build no longer has are removed, then index.html is invalidated at the edge.
# - The AWS identity is checked by scripts/tf.sh (right account, never root).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
die() { printf 'spa-push: %s\n' "$*" >&2; exit 1; }
say() { printf 'spa-push: %s\n' "$*"; }

[[ -z "$(git -C "$ROOT" status --porcelain --untracked-files=no)" ]] \
  || die "the working tree has uncommitted changes: commit them, so the site matches a commit"

outputs="$("$ROOT/scripts/tf.sh" dev output-json)"
read -r bucket distribution < <(printf '%s' "$outputs" | python3 -c '
import json, sys
w = (json.load(sys.stdin).get("workload") or {}).get("value")
if not w:
    sys.exit("spa-push: the workload is off: set workload = true and apply the dev stack first")
print(w["spa_bucket"], w["distribution_id"])
')
[[ -n "${bucket:-}" ]] || die "could not read the dev stack's edge outputs"

say "building the SPA from $(git -C "$ROOT" rev-parse --short=12 HEAD)"
(cd "$ROOT/frontend" && npm ci --ignore-scripts --no-audit --no-fund >/dev/null && npm run build >/dev/null)
DIST="$ROOT/frontend/dist"
[[ -f "$DIST/index.html" ]] || die "the build produced no index.html"

S3="s3://$bucket"
say "uploading to $bucket"
aws s3 sync "$DIST/assets" "$S3/assets" --region us-east-1 --only-show-errors \
  --cache-control "public, max-age=31536000, immutable"
aws s3 sync "$DIST" "$S3" --region us-east-1 --only-show-errors \
  --exclude "assets/*" --exclude "index.html" --cache-control "no-cache"
# index.html last, so it never names assets that are not there yet.
aws s3 cp "$DIST/index.html" "$S3/index.html" --region us-east-1 --only-show-errors \
  --cache-control "no-cache" --content-type "text/html; charset=utf-8"

# Remove what this build no longer has (old versions expire after a week).
stale="$(aws s3api list-objects-v2 --region us-east-1 --bucket "$bucket" --query 'Contents[].Key' --output json \
  | python3 -c '
import json, os, sys
root = sys.argv[1]
built = {os.path.relpath(os.path.join(d, f), root) for d, _, fs in os.walk(root) for f in fs}
for key in json.load(sys.stdin) or []:
    if key not in built:
        print(key)
' "$DIST")"
if [[ -n "$stale" ]]; then
  while IFS= read -r key; do
    aws s3 rm "$S3/$key" --region us-east-1 --only-show-errors
  done <<< "$stale"
  say "removed $(printf '%s\n' "$stale" | wc -l) file(s) the new build no longer has"
fi

aws cloudfront create-invalidation --distribution-id "$distribution" --paths "/index.html" "/" \
  --query 'Invalidation.Id' --output text >/dev/null
say "published; index.html invalidated at the edge"
