#!/usr/bin/env bash
# Build the API and dbadmin images for AWS, push them to ECR and pin them by digest
# (make images-push; Phase 4, ADR-0026).
#
# - Images are built from a clean, committed tree and tagged with the commit, so an image always
#   matches a commit. Tags in ECR are immutable: a commit already pushed is reused, not rebuilt.
# - Terraform references images only by digest. This writes
#   terraform/environments/dev/images.auto.tfvars (git-ignored), which the next plan picks up.
# - The AWS identity is checked by scripts/tf.sh (right account, never root); Docker's ECR login
#   is a 12-hour token that is removed again at the end.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TFVARS="$ROOT/terraform/environments/dev/images.auto.tfvars"
CA="$ROOT/backend/certs/rds-global-bundle.pem"
PLATFORM="linux/amd64"

die() { printf 'images-push: %s\n' "$*" >&2; exit 1; }
say() { printf 'images-push: %s\n' "$*"; }

[[ -f "$CA" ]] || die "backend/certs/rds-global-bundle.pem is missing: run make rds-ca and commit it"
[[ -z "$(git -C "$ROOT" status --porcelain --untracked-files=no)" ]] \
  || die "the working tree has uncommitted changes: commit them, so the image matches a commit"
TAG="$(git -C "$ROOT" rev-parse --short=12 HEAD)"

outputs="$("$ROOT/scripts/tf.sh" dev output-json)"
api_repo="$(printf '%s' "$outputs" | python3 -c 'import json,sys; print(json.load(sys.stdin)["ecr_api_repository_url"]["value"])')"
dbadmin_repo="$(printf '%s' "$outputs" | python3 -c 'import json,sys; print(json.load(sys.stdin)["ecr_dbadmin_repository_url"]["value"])')"
registry="${api_repo%%/*}"
region="$(printf '%s' "$registry" | cut -d. -f4)"

aws ecr get-login-password --region "$region" | docker login --username AWS --password-stdin "$registry" >/dev/null
trap 'docker logout "$registry" >/dev/null 2>&1 || true' EXIT

# Push <repo>:<TAG> unless it exists, then print <repo>@<digest>.
push() {
  local repo="$1"; shift
  local name="${repo#*/}" digest
  digest="$(aws ecr describe-images --region "$region" --repository-name "$name" \
    --image-ids imageTag="$TAG" --query 'imageDetails[0].imageDigest' --output text 2>/dev/null || true)"
  if [[ -z "$digest" || "$digest" == "None" ]]; then
    say "building $name:$TAG" >&2
    docker build --quiet --platform "$PLATFORM" --tag "$repo:$TAG" "$@" >/dev/null
    say "pushing $name:$TAG" >&2
    docker push --quiet "$repo:$TAG" >/dev/null
    digest="$(aws ecr describe-images --region "$region" --repository-name "$name" \
      --image-ids imageTag="$TAG" --query 'imageDetails[0].imageDigest' --output text)"
  else
    say "$name:$TAG is already in ECR; reusing it" >&2
  fi
  [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || die "no digest for $name:$TAG"
  printf '%s@%s' "$repo" "$digest"
}

api_image="$(push "$api_repo" "$ROOT/backend")"
dbadmin_image="$(push "$dbadmin_repo" -f "$ROOT/db/Dockerfile" --build-context certs="$ROOT/backend/certs" "$ROOT/db")"

umask 077
cat > "$TFVARS" <<TF
# Written by scripts/images-push.sh for commit $TAG. Git-ignored; images only by digest.
api_image     = "$api_image"
dbadmin_image = "$dbadmin_image"
TF
say "pinned in ${TFVARS#"$ROOT"/}:"
say "  api     $api_image"
say "  dbadmin $dbadmin_image"
