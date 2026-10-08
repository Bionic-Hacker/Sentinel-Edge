#!/usr/bin/env bash
# Every container image is pinned as name:tag@sha256:digest (Phase 8). A pin never changes by
# itself, so security fixes published under the same tag are not picked up. This lists each pin
# and whether its tag now points to a newer digest:
#
#   make image-digests            report only
#   make image-digests UPDATE=1   rewrite stale pins in place (review the diff, rerun make scan)
#
# Dependabot updates FROM lines only; these pins live in build arguments, Compose, CI and scripts.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

files=(Makefile docker-compose.yml .github/workflows/ci.yml backend/Dockerfile frontend/Dockerfile
       scripts/scan.sh scripts/with-test-db.sh)
mapfile -t pins < <(grep -ohE '[a-z0-9][a-z0-9./-]*:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}' "${files[@]}" | sort -u)

stale=0
for pin in "${pins[@]}"; do
  ref="${pin%@*}"
  have="${pin#*@}"
  now="$(docker buildx imagetools inspect "$ref" --format '{{json .Manifest.Digest}}' | tr -d '"')"
  if [[ "$now" == "$have" ]]; then
    printf '  current  %s\n' "$ref"
  else
    stale=$((stale + 1))
    printf '  STALE    %s\n           pinned %s\n           now    %s\n' "$ref" "$have" "$now"
    if [[ "${UPDATE:-0}" == 1 ]]; then
      sed -i "s|${ref}@${have}|${ref}@${now}|g" "${files[@]}"
    fi
  fi
done
echo "${#pins[@]} pins, ${stale} stale"
